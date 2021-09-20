package wavefront

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

//Wavefronter is an interface
type Wavefronter interface {
	NewRequest(method, path string, params *map[string]string, body []byte) (*http.Request, error)
	Do()
}

//Wavefront API config
type Config struct {
	Address       string
	Token         string
	HttpProxy     string
	SkipTLSVerify bool
}

//Wavefront API client
type Client struct {
	Config        *Config
	BaseURL       *url.URL
	RetryDuration int
	httpClient    *http.Client
}

type restError struct {
	error
	statusCode int
}

type Settings struct {
	payloadPtr     interface{}
	responsePtr    interface{}
	params         map[string]string
	directResponse bool
}

type doOption func(d *Settings)

//Simple Wavefront Client
func NewClient(config *Config) (*Client, error) {
	baseURL, err := url.Parse(config.Address)

	if err != nil {
		return nil, err
	}

	c := &Client{
		Config:        config,
		BaseURL:       baseURL,
		RetryDuration: 0,
		httpClient:    &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSNextProto: map[string]func(authority string, c *tls.Conn) http.RoundTripper{}}},
	}
	return c, nil
}

//creates a request object to interact with wavefront API
func (c Client) NewRequest(method, path string, params *map[string]string, body []byte) (*http.Request, error) {
	rel, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	currentUrl := c.BaseURL.ResolveReference(rel)

	if params != nil {
		q := currentUrl.Query()
		for k, v := range *params {
			q.Set(k, v)
		}
		currentUrl.RawQuery = q.Encode()
	}

	req, err := http.NewRequest(method, currentUrl.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.Config.Token))
	req.Header.Add("Accept", "application/json")
	if body != nil {
		req.Header.Add("Content-Type", "application/json")
		req.Body = ioutil.NopCloser(bytes.NewReader(body))
	}
	return req, nil
}

func httpStatusCode(err error) int {
	re, ok := err.(*restError)
	if !ok {
		return 0
	}
	return re.statusCode
}

// NotFound returns true if err is because the resource doesn't exist.
func NotFound(err error) bool {
	return httpStatusCode(err) == 404
}

// doResponse specifies that the response of the rest API call should be stored
// in the struct pointed to by ptr.
func doResponse(ptr interface{}) doOption {
	return func(d *Settings) {
		d.responsePtr = ptr
		d.directResponse = false
		d.params = map[string]string{"limit": "100"}
	}
}

func doRest(
	method string,
	url string,
	client Wavefronter,
	options ...doOption) (err error) {
	var settings Settings
	settings.applyOptions(options)
	var payload []byte
	if settings.payloadPtr != nil {
		payload, err = json.Marshal(settings.payloadPtr)
		if err != nil {
			return
		}
	}
	var req *http.Request
	if len(settings.params) == 0 {
		req, err = client.NewRequest(method, url, nil, payload)
	} else {
		req, err = client.NewRequest(method, url, &settings.params, payload)
	}
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Close()
	if settings.responsePtr != nil {
		decoder := json.NewDecoder(resp)
		pointToZeroValue(settings.responsePtr)
		if settings.directResponse {
			return decoder.Decode(settings.responsePtr)
		}
		return decoder.Decode(jsonResponseWrapper(settings.responsePtr))
	}
	return nil
}

func doRestAll(method string, url string, Client Wavefronter, options ...doOption) {
	var payload []byte
	var req *http.Request
	req, err := Client.NewRequest(method, url, nil, payload)
	if err != nil {
		return
	}
	response, err := Client.Do(req)
	if err != nil {
		return
	}
	moreItems := true
	for moreItems {
		response, err := Client.NewRequest(method, url, nil, payload)
		if err != nil {
			return err
		}
	}

}

func (c Client) Do(req *http.Request) (io.ReadCloser, error) {
	retries := 0
	maxRetries := 10
	var buf []byte
	var err error
	if req.Body != nil {
		buf, err = ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		// reset the body since we read it already
		req.Body = ioutil.NopCloser(bytes.NewReader(buf))
	}

	for {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		// Per RFC Spec these are safe to accept as valid status codes as they all intent that the request was fulfilled
		// 200 -> OK
		// 201 -> Created
		// 202 -> Accepted
		// 203 -> Accepted but payload has been modified  via transforming proxy
		// 204 -> No Content
		if !(resp.StatusCode >= 200 && resp.StatusCode <= 204) {
			// back off and retry on 406 only
			if retries <= maxRetries && resp.StatusCode == 406 {
				retries++
				// replay the buffer back into the body for retry
				if req.Body != nil {
					req.Body = ioutil.NopCloser(bytes.NewReader(buf))
				}
				sleepTime := c.getSleepTime(retries)
				time.Sleep(sleepTime)
				continue
			}
			body, err := ioutil.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				re := newRestError(
					fmt.Errorf("server returned %s\n", resp.Status),
					resp.StatusCode)
				return nil, re
			}
			re := newRestError(
				fmt.Errorf("server returned %s\n%s\n", resp.Status, string(body)),
				resp.StatusCode)
			return nil, re
		}
		return resp.Body, nil
	}
}

func newRestError(err error, statusCode int) error {
	return &restError{error: err, statusCode: statusCode}
}

func (c *Client) getSleepTime(retries int) time.Duration {
	defaultSleep := time.Duration(c.RetryDuration) * time.Millisecond
	// Add some jitter, add 500ms * our retry, convert to MS
	jitter := time.Duration(rand.Int63n(50)+50) * time.Millisecond
	duration := time.Duration(500*retries) * time.Millisecond
	sleep := duration + jitter
	if sleep >= defaultSleep {
		return defaultSleep
	}
	return sleep
}
