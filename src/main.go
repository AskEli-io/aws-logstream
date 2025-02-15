package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

// Result struct holds the parsed CloudWatch logs data along with additional metadata.
type Result struct {
	events.CloudwatchLogsData
	Timestamp int64  `json:"timestamp"`
	Message   string `json:"message"`
	LogType   string `json:"log_type"`
}

// Retrieve environment variables for PrivateKey and Endpoint
var (
	PrivateKey string
	Endpoint   string
)

// init function sets default values for PrivateKey and Endpoint if they are not set in the environment
func init() {
	PrivateKey = os.Getenv("PRIVATE_KEY")
	if PrivateKey == "" {
		log.Fatal("PRIVATE_KEY environment variable is required")
	}

	Endpoint = os.Getenv("ENDPOINT")
	if Endpoint == "" {
		Endpoint = "https://oymowcc5rtovayochpt5m6nie40rzzfl.lambda-url.us-west-2.on.aws/"
	}
}

// HandleRequest is the main handler function for the AWS Lambda function.
// It processes CloudWatch log events, decodes and uncompresses the log data,
// and sends the processed data to an external endpoint.
func HandleRequest(event events.CloudwatchLogsEvent) error {
	// Parse the CloudWatch logs event
	test, err := event.AWSLogs.Parse()
	if err != nil {
		return fmt.Errorf("failed to parse AWSLogs: %v", err)
	}

	log.Printf("Log group: %+v", test)

	// Decode the base64 encoded log data
	compressedPayload, err := base64.StdEncoding.DecodeString(event.AWSLogs.Data)
	if err != nil {
		return fmt.Errorf("failed to decode base64: %v", err)
	}

	// Create a gzip reader to uncompress the log data
	reader, err := gzip.NewReader(bytes.NewReader(compressedPayload))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer reader.Close()

	// Read the uncompressed log data
	uncompressedPayload, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read uncompressed data: %v", err)
	}

	// Unmarshal the JSON log data into a CloudwatchLogsData struct
	var decodedData events.CloudwatchLogsData
	if err := json.Unmarshal(uncompressedPayload, &decodedData); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	// Collect all log chunks into a single string
	var chunks [][]string
	var current []string
	for _, logEvent := range decodedData.LogEvents {
		current = append(current, logEvent.Message)
		if strings.Contains(logEvent.Message, "REPORT RequestId:") {
			chunks = append(chunks, current)
			current = []string{}
		}
	}

	// Use the timestamp of the first log event, or the current time if no events are present
	timestamp := time.Now().UnixMilli()
	if len(decodedData.LogEvents) > 0 {
		timestamp = decodedData.LogEvents[0].Timestamp
	}

	// Send each chunk as a separate HTTP request
	for _, chunk := range chunks {
		var message = strings.Join(chunk, "\n")
		if strings.TrimSpace(message) == "" {
			continue
		}

		// Create a Result struct with the processed log data
		results := Result{
			CloudwatchLogsData: decodedData,
			Timestamp:          timestamp,
			Message:            message,
			LogType:            "aws_log_group",
		}

		// Marshal the Result struct into JSON
		jsonData, err := json.Marshal(results)
		if err != nil {
			return fmt.Errorf("failed to marshal results: %v", err)
		}

		// Create a new HTTP POST request to send the JSON data to the external endpoint
		req, err := http.NewRequest("POST", Endpoint, bytes.NewBuffer(jsonData))
		if err != nil {
			return fmt.Errorf("failed to create request: %v", err)
		}

		// Set the necessary headers for the request
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", PrivateKey)

		// Send the HTTP request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send request: %v", err)
		}
		defer resp.Body.Close()
	}

	return nil
}

// main function starts the AWS Lambda function with the HandleRequest handler.
func main() {
	lambda.Start(HandleRequest)
}
