package executor

import (
	"encoding/json"
	"html"
	"regexp"
	"strings"

	qoderauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qoder"
)

const (
	qoderToolCallOpen  = "<tool_call>"
	qoderToolCallClose = "</tool_call>"
)

var (
	qoderFunctionPattern  = regexp.MustCompile(`(?s)<function=([^>]+)>(.*?)</function>`)
	qoderParameterPattern = regexp.MustCompile(`(?s)<parameter=([^>]+)>(.*?)</parameter>`)
)

type qoderToolCallAdapter struct {
	textBuffer string
	callBuffer string
	inCall     bool
	toolIndex  int
	sawTool    bool
	lastChunk  []byte
}

type qoderToolFragment struct {
	text string
	call *qoderFunctionCall
}

type qoderFunctionCall struct {
	name      string
	arguments string
}

func (a *qoderToolCallAdapter) convert(payload []byte) ([][]byte, error) {
	var chunk map[string]json.RawMessage
	if err := json.Unmarshal(payload, &chunk); err != nil {
		return [][]byte{payload}, nil
	}
	choicesRaw, ok := chunk["choices"]
	if !ok {
		return [][]byte{payload}, nil
	}
	var choices []json.RawMessage
	if err := json.Unmarshal(choicesRaw, &choices); err != nil || len(choices) == 0 {
		return [][]byte{payload}, nil
	}
	var firstChoice map[string]json.RawMessage
	if err := json.Unmarshal(choices[0], &firstChoice); err != nil {
		return [][]byte{payload}, nil
	}
	var delta map[string]json.RawMessage
	if err := json.Unmarshal(firstChoice["delta"], &delta); err != nil {
		return [][]byte{payload}, nil
	}
	var content string
	if err := json.Unmarshal(delta["content"], &content); err != nil {
		if a.sawTool && qoderHasFinishReason(firstChoice) {
			return [][]byte{qoderSetFinishReason(payload, "tool_calls")}, nil
		}
		return [][]byte{payload}, nil
	}

	a.lastChunk = payload
	fragments := a.feed(content)
	if len(fragments) == 0 {
		if content == "" {
			if a.sawTool && qoderHasFinishReason(firstChoice) {
				return [][]byte{qoderSetFinishReason(payload, "tool_calls")}, nil
			}
			return [][]byte{payload}, nil
		}
		return nil, nil
	}
	result := make([][]byte, 0, len(fragments))
	for i, fragment := range fragments {
		encoded, err := a.rewrite(payload, fragment, i == len(fragments)-1)
		if err != nil {
			return nil, err
		}
		result = append(result, encoded)
	}
	return result, nil
}

func (a *qoderToolCallAdapter) rewrite(payload []byte, fragment qoderToolFragment, last bool) ([]byte, error) {
	var chunk map[string]json.RawMessage
	if err := json.Unmarshal(payload, &chunk); err != nil {
		return nil, err
	}
	var choices []json.RawMessage
	if err := json.Unmarshal(chunk["choices"], &choices); err != nil || len(choices) == 0 {
		return payload, nil
	}
	var firstChoice map[string]json.RawMessage
	if err := json.Unmarshal(choices[0], &firstChoice); err != nil {
		return nil, err
	}
	var delta map[string]json.RawMessage
	if err := json.Unmarshal(firstChoice["delta"], &delta); err != nil {
		return nil, err
	}
	return a.chunkWithFragment(chunk, choices, firstChoice, delta, fragment, last)
}

func (a *qoderToolCallAdapter) flush() ([][]byte, error) {
	fragments := a.flushFragments()
	result := make([][]byte, 0, len(fragments))
	for i, fragment := range fragments {
		encoded, err := a.rewrite(a.lastChunk, fragment, i == len(fragments)-1)
		if err != nil {
			return nil, err
		}
		result = append(result, encoded)
	}
	return result, nil
}

func (a *qoderToolCallAdapter) feed(input string) []qoderToolFragment {
	var fragments []qoderToolFragment
	for input != "" {
		if !a.inCall {
			combined := a.textBuffer + input
			a.textBuffer = ""
			start := strings.Index(combined, qoderToolCallOpen)
			if start < 0 {
				keep := qoderMarkerPrefixSuffix(combined, qoderToolCallOpen)
				if keep < len(combined) {
					fragments = appendQoderText(fragments, combined[:len(combined)-keep])
				}
				a.textBuffer = combined[len(combined)-keep:]
				break
			}
			fragments = appendQoderText(fragments, combined[:start])
			input = combined[start+len(qoderToolCallOpen):]
			a.inCall = true
			continue
		}

		combined := a.callBuffer + input
		a.callBuffer = ""
		end := strings.Index(combined, qoderToolCallClose)
		if end < 0 {
			a.callBuffer = combined
			break
		}
		callBody := combined[:end]
		if call, ok := parseQoderFunctionCall(callBody); ok {
			fragments = append(fragments, qoderToolFragment{call: &call})
		} else {
			fragments = appendQoderText(fragments, qoderToolCallOpen+callBody+qoderToolCallClose)
		}
		input = combined[end+len(qoderToolCallClose):]
		a.inCall = false
	}
	return fragments
}

func (a *qoderToolCallAdapter) flushFragments() []qoderToolFragment {
	if a.inCall {
		text := qoderToolCallOpen + a.callBuffer
		a.inCall = false
		a.callBuffer = ""
		return appendQoderText(nil, text)
	}
	text := a.textBuffer
	a.textBuffer = ""
	return appendQoderText(nil, text)
}

func appendQoderText(fragments []qoderToolFragment, text string) []qoderToolFragment {
	if text != "" {
		return append(fragments, qoderToolFragment{text: text})
	}
	return fragments
}

func qoderMarkerPrefixSuffix(value, marker string) int {
	max := len(marker) - 1
	if len(value) < max {
		max = len(value)
	}
	for size := max; size > 0; size-- {
		if strings.HasSuffix(value, marker[:size]) {
			return size
		}
	}
	return 0
}

func parseQoderFunctionCall(value string) (qoderFunctionCall, bool) {
	match := qoderFunctionPattern.FindStringSubmatch(value)
	if len(match) != 3 {
		return qoderFunctionCall{}, false
	}
	call := qoderFunctionCall{name: strings.TrimSpace(match[1])}
	if call.name == "" {
		return qoderFunctionCall{}, false
	}
	arguments := make(map[string]any)
	for _, parameter := range qoderParameterPattern.FindAllStringSubmatch(match[2], -1) {
		name := strings.TrimSpace(parameter[1])
		if name == "" {
			continue
		}
		value := strings.TrimSpace(html.UnescapeString(parameter[2]))
		var decoded any
		if json.Unmarshal([]byte(value), &decoded) != nil {
			decoded = value
		}
		arguments[name] = decoded
	}
	encoded, err := json.Marshal(arguments)
	if err != nil {
		return qoderFunctionCall{}, false
	}
	call.arguments = string(encoded)
	return call, true
}

func (a *qoderToolCallAdapter) chunkWithFragment(
	chunk map[string]json.RawMessage,
	choices []json.RawMessage,
	firstChoice, delta map[string]json.RawMessage,
	fragment qoderToolFragment,
	last bool,
) ([]byte, error) {
	deltaCopy := cloneQoderRawMessageMap(delta)
	choiceCopy := cloneQoderRawMessageMap(firstChoice)
	chunkCopy := cloneQoderRawMessageMap(chunk)
	if fragment.call == nil {
		content, _ := json.Marshal(fragment.text)
		deltaCopy["content"] = content
	} else {
		delete(deltaCopy, "content")
		index := a.toolIndex
		a.toolIndex++
		a.sawTool = true
		call := map[string]any{
			"index": index,
			"id":    "call_" + qoderauth.NewID(),
			"type":  "function",
			"function": map[string]string{
				"name":      fragment.call.name,
				"arguments": fragment.call.arguments,
			},
		}
		calls, err := json.Marshal([]any{call})
		if err != nil {
			return nil, err
		}
		deltaCopy["tool_calls"] = calls
	}
	encodedDelta, err := json.Marshal(deltaCopy)
	if err != nil {
		return nil, err
	}
	choiceCopy["delta"] = encodedDelta
	if qoderHasFinishReason(choiceCopy) {
		if last && a.sawTool {
			finishReason, _ := json.Marshal("tool_calls")
			choiceCopy["finish_reason"] = finishReason
		} else if !last {
			choiceCopy["finish_reason"] = json.RawMessage("null")
		}
	}
	encodedChoice, err := json.Marshal(choiceCopy)
	if err != nil {
		return nil, err
	}
	newChoices := append([]json.RawMessage(nil), choices...)
	newChoices[0] = encodedChoice
	encodedChoices, err := json.Marshal(newChoices)
	if err != nil {
		return nil, err
	}
	chunkCopy["choices"] = encodedChoices
	return json.Marshal(chunkCopy)
}

func cloneQoderRawMessageMap(input map[string]json.RawMessage) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func qoderHasFinishReason(choice map[string]json.RawMessage) bool {
	finishReason, ok := choice["finish_reason"]
	return ok && string(finishReason) != "null"
}

func qoderSetFinishReason(payload []byte, reason string) []byte {
	var chunk map[string]json.RawMessage
	if json.Unmarshal(payload, &chunk) != nil {
		return payload
	}
	var choices []json.RawMessage
	if json.Unmarshal(chunk["choices"], &choices) != nil || len(choices) == 0 {
		return payload
	}
	var choice map[string]json.RawMessage
	if json.Unmarshal(choices[0], &choice) != nil {
		return payload
	}
	value, _ := json.Marshal(reason)
	choice["finish_reason"] = value
	choices[0], _ = json.Marshal(choice)
	chunk["choices"], _ = json.Marshal(choices)
	result, err := json.Marshal(chunk)
	if err != nil {
		return payload
	}
	return result
}
