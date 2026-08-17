export const GUI_NODE_RESULT_MARKER = "__DEVSPACE_V2_GUI_JSON__";

/**
 * Generic macOS Accessibility node. It intentionally knows nothing about
 * Chrome, Finder, email, Jira, or any other application. Elements are flattened
 * from the front window and addressed by observation index. The broker verifies
 * a generation and element fingerprint before asking this node to act.
 */
export const GUI_NODE_APPLESCRIPT_SOURCE = String.raw`
property resultMarker : "__DEVSPACE_V2_GUI_JSON__"

on run argv
  try
    if (count of argv) is 0 then return my emitError("PRECONDITION_FAILED", "Missing GUI node operation.")
    set operationName to item 1 of argv
    if operationName is "capabilities" then
      return my capabilitiesResult()
    else if operationName is "observe" then
      set maximumElements to 100
      if (count of argv) ≥ 2 then set maximumElements to item 2 of argv as integer
      return my observationResult(maximumElements)
    else if operationName is "act" then
      return my actResult(argv)
    else
      return my emitError("PRECONDITION_FAILED", "Unsupported GUI node operation: " & operationName)
    end if
  on error errorMessage number errorNumber
    if errorMessage starts with "__GUI_STATE_CHANGED__" then
      return my emitError("GUI_STATE_CHANGED", text 22 thru -1 of errorMessage)
    else if errorMessage starts with "__ACTION_UNAVAILABLE__" then
      return my emitError("CAPABILITY_UNAVAILABLE", text 23 thru -1 of errorMessage)
    else
      return my emitError("MCP_PROVIDER_ERROR", errorMessage & " (" & errorNumber & ")")
    end if
  end try
end run

on capabilitiesResult()
  set accessibilityEnabled to false
  set frontName to ""
  set frontProcessId to 0
  set probeError to ""
  try
    tell application "System Events"
      set accessibilityEnabled to UI elements enabled as boolean
      if accessibilityEnabled then
        set frontProcess to first application process whose frontmost is true
        set frontName to name of frontProcess as text
        set frontProcessId to (unix id of frontProcess) as integer
      end if
    end tell
  on error errorMessage number errorNumber
    set accessibilityEnabled to false
    set probeError to my boundedText(errorMessage & " (" & errorNumber & ")", 300)
  end try
  set payload to "{\"platform\":\"macos\",\"accessibility\":" & my jsonBoolean(accessibilityEnabled) & ",\"screenCapture\":\"not_probed\",\"frontmostProcess\":{" & ¬
    "\"name\":" & my jsonString(frontName) & ",\"pid\":" & frontProcessId & "},\"probeError\":" & my jsonString(probeError) & "}"
  return my emitSuccess(payload)
end capabilitiesResult

on observationResult(maximumElements)
  if maximumElements < 1 then set maximumElements to 1
  if maximumElements > 1000 then set maximumElements to 1000
  try
    tell application "System Events" to set accessibilityEnabled to UI elements enabled as boolean
  on error errorMessage number errorNumber
    return my emitError("CAPABILITY_UNAVAILABLE", "macOS Accessibility probe failed: " & errorMessage & " (" & errorNumber & ")")
  end try
  if not accessibilityEnabled then return my emitError("CAPABILITY_UNAVAILABLE", "macOS Accessibility UI scripting is disabled for this GUI node.")
  tell application "System Events"
    set frontProcess to first application process whose frontmost is true
    set processName to my safeName(frontProcess)
    set processId to (unix id of frontProcess) as integer
    set bundleId to my safeBundleIdentifier(frontProcess)
    set windowJson to "null"
    set elementJsonItems to {}
    set totalElements to 0
    set omittedElements to 0
    set wasTruncated to false
    if (count of windows of frontProcess) > 0 then
      set frontWindow to front window of frontProcess
      set windowJson to my windowJson(frontWindow)
      set maximumScan to maximumElements * 8
      if maximumScan < 200 then set maximumScan to 200
      if maximumScan > 4000 then set maximumScan to 4000
      set traversalResult to my boundedElements(frontWindow, maximumScan)
      set flattenedElements to item 1 of traversalResult
      set traversalTruncated to item 2 of traversalResult
      set totalElements to (count of flattenedElements) + 1
      set windowElement to my elementJson(frontWindow, 0)
      if my elementMeaningful(frontWindow) then set end of elementJsonItems to windowElement
      repeat with elementIndex from 1 to count of flattenedElements
        set currentElement to item elementIndex of flattenedElements
        if my elementMeaningful(currentElement) then
          if (count of elementJsonItems) < maximumElements then
            set end of elementJsonItems to my elementJson(currentElement, elementIndex)
          else
            set omittedElements to omittedElements + 1
            set wasTruncated to true
          end if
        end if
      end repeat
      if traversalTruncated then
        set omittedElements to omittedElements + 1
        set wasTruncated to true
      end if
    end if
    set payload to "{\"application\":{" & ¬
      "\"name\":" & my jsonString(processName) & "," & ¬
      "\"bundleIdentifier\":" & my jsonString(bundleId) & "," & ¬
      "\"pid\":" & processId & "}," & ¬
      "\"window\":" & windowJson & "," & ¬
      "\"elements\":[" & my joinText(elementJsonItems, ",") & "]," & ¬
      "\"totalElements\":" & totalElements & "," & ¬
      "\"omittedElements\":" & omittedElements & "," & ¬
      "\"truncated\":" & my jsonBoolean(wasTruncated) & "}"
    return my emitSuccess(payload)
  end tell
end observationResult

on actResult(argv)
  if (count of argv) < 13 then return my emitError("PRECONDITION_FAILED", "Incomplete GUI action arguments.")
  set elementIndex to item 2 of argv as integer
  set actionType to item 3 of argv as text
  set actionName to my decodeBase64(item 4 of argv as text)
  set actionValue to my decodeBase64(item 5 of argv as text)
  set modifierText to item 6 of argv as text
  set keyCodeValue to item 7 of argv as integer
  set expectedPid to item 8 of argv as integer
  set expectedWindowTitle to my decodeBase64(item 9 of argv as text)
  set expectedRole to my decodeBase64(item 10 of argv as text)
  set expectedName to my decodeBase64(item 11 of argv as text)
  set expectedDescription to my decodeBase64(item 12 of argv as text)
  set expectedSubrole to my decodeBase64(item 13 of argv as text)

  try
    tell application "System Events" to set accessibilityEnabled to UI elements enabled as boolean
  on error errorMessage number errorNumber
    return my emitError("CAPABILITY_UNAVAILABLE", "macOS Accessibility probe failed: " & errorMessage & " (" & errorNumber & ")")
  end try
  if not accessibilityEnabled then return my emitError("CAPABILITY_UNAVAILABLE", "macOS Accessibility UI scripting is disabled for this GUI node.")
  tell application "System Events"
    set frontProcess to first application process whose frontmost is true
    if ((unix id of frontProcess) as integer) is not expectedPid then error "__GUI_STATE_CHANGED__frontmost process changed"
    if (count of windows of frontProcess) is 0 then error "__GUI_STATE_CHANGED__front window disappeared"
    set frontWindow to front window of frontProcess
    if my safeName(frontWindow) is not expectedWindowTitle then error "__GUI_STATE_CHANGED__front window changed"

    set currentElement to missing value
    if elementIndex is 0 then
      set currentElement to frontWindow
    else if elementIndex > 0 then
      set currentElement to my elementAtBoundedIndex(frontWindow, elementIndex)
      if currentElement is missing value then error "__GUI_STATE_CHANGED__element index disappeared"
    end if

    if elementIndex ≥ 0 then
      if my safeRole(currentElement) is not expectedRole then error "__GUI_STATE_CHANGED__element role changed"
      if my safeSubrole(currentElement) is not expectedSubrole then error "__GUI_STATE_CHANGED__element subrole changed"
      if my safeName(currentElement) is not expectedName then error "__GUI_STATE_CHANGED__element name changed"
      if my safeDescription(currentElement) is not expectedDescription then error "__GUI_STATE_CHANGED__element description changed"
    end if

    if actionType is "perform" then
      if elementIndex < 0 or actionName is "" then error "__ACTION_UNAVAILABLE__perform requires an element and actionName"
      perform action actionName of currentElement
    else if actionType is "press" or actionType is "click" then
      if elementIndex < 0 then error "__ACTION_UNAVAILABLE__press requires an element"
      perform action "AXPress" of currentElement
    else if actionType is "set_value" then
      if elementIndex < 0 then error "__ACTION_UNAVAILABLE__set_value requires an element"
      set value of currentElement to actionValue
    else if actionType is "focus" then
      if elementIndex < 0 then error "__ACTION_UNAVAILABLE__focus requires an element"
      set focused of currentElement to true
    else if actionType is "keystroke" then
      if elementIndex ≥ 0 then
        try
          set focused of currentElement to true
        end try
      end if
      keystroke actionValue using my modifierList(modifierText)
    else if actionType is "key_code" then
      if keyCodeValue < 0 then error "__ACTION_UNAVAILABLE__key_code requires keyCode"
      key code keyCodeValue using my modifierList(modifierText)
    else
      error "__ACTION_UNAVAILABLE__unsupported action type: " & actionType
    end if
  end tell
  return my emitSuccess("{\"performed\":true,\"actionType\":" & my jsonString(actionType) & "}")
end actResult

on boundedElements(guiRoot, maximumScan)
  if maximumScan < 1 then return {{}, false}
  set pendingElements to {}
  tell application "System Events"
    try
      set rootChildren to UI elements of guiRoot
      repeat with childElement in rootChildren
        set end of pendingElements to contents of childElement
      end repeat
    end try
  end tell
  set flattenedElements to {}
  set pendingIndex to 1
  set traversalTruncated to false
  repeat while pendingIndex ≤ (count of pendingElements)
    if (count of flattenedElements) ≥ maximumScan then
      set traversalTruncated to true
      exit repeat
    end if
    set currentElement to item pendingIndex of pendingElements
    set end of flattenedElements to currentElement
    tell application "System Events"
      try
        set childElements to UI elements of currentElement
        repeat with childElement in childElements
          set end of pendingElements to contents of childElement
        end repeat
      end try
    end tell
    set pendingIndex to pendingIndex + 1
  end repeat
  if pendingIndex ≤ (count of pendingElements) then set traversalTruncated to true
  return {flattenedElements, traversalTruncated}
end boundedElements

on elementAtBoundedIndex(guiRoot, elementIndex)
  if elementIndex < 1 then return missing value
  set traversalResult to my boundedElements(guiRoot, elementIndex)
  set flattenedElements to item 1 of traversalResult
  if elementIndex > (count of flattenedElements) then return missing value
  return item elementIndex of flattenedElements
end elementAtBoundedIndex

on elementMeaningful(guiElement)
  set roleText to my safeRole(guiElement)
  if roleText is not "" and roleText is not "AXGroup" and roleText is not "AXUnknown" then return true
  if my safeName(guiElement) is not "" then return true
  if my safeDescription(guiElement) is not "" then return true
  if my safeValue(guiElement) is not "" then return true
  if my safeFocused(guiElement) then return true
  if (count of my safeActions(guiElement)) > 0 then return true
  return false
end elementMeaningful

on elementJson(guiElement, elementIndex)
  set actionNames to my safeActions(guiElement)
  return "{" & ¬
    "\"elementId\":\"e" & elementIndex & "\"," & ¬
    "\"index\":" & elementIndex & "," & ¬
    "\"role\":" & my jsonString(my safeRole(guiElement)) & "," & ¬
    "\"subrole\":" & my jsonString(my safeSubrole(guiElement)) & "," & ¬
    "\"name\":" & my jsonString(my safeName(guiElement)) & "," & ¬
    "\"description\":" & my jsonString(my safeDescription(guiElement)) & "," & ¬
    "\"value\":" & my jsonString(my safeValue(guiElement)) & "," & ¬
    "\"enabled\":" & my jsonNullableBoolean(my safeEnabled(guiElement)) & "," & ¬
    "\"focused\":" & my jsonBoolean(my safeFocused(guiElement)) & "," & ¬
    "\"position\":" & my safePair(guiElement, "position") & "," & ¬
    "\"size\":" & my safePair(guiElement, "size") & "," & ¬
    "\"actions\":[" & my jsonStringArray(actionNames) & "]}"
end elementJson

on windowJson(guiWindow)
  return "{" & ¬
    "\"title\":" & my jsonString(my safeName(guiWindow)) & "," & ¬
    "\"role\":" & my jsonString(my safeRole(guiWindow)) & "," & ¬
    "\"subrole\":" & my jsonString(my safeSubrole(guiWindow)) & "," & ¬
    "\"position\":" & my safePair(guiWindow, "position") & "," & ¬
    "\"size\":" & my safePair(guiWindow, "size") & "}"
end windowJson

on safeRole(guiElement)
  tell application "System Events"
    try
      return my boundedText(role of guiElement as text, 120)
    on error
      return ""
    end try
  end tell
end safeRole

on safeSubrole(guiElement)
  tell application "System Events"
    try
      return my boundedText(subrole of guiElement as text, 120)
    on error
      return ""
    end try
  end tell
end safeSubrole

on safeName(guiElement)
  tell application "System Events"
    try
      set currentValue to name of guiElement
      if currentValue is missing value then return ""
      return my boundedText(currentValue as text, 240)
    on error
      return ""
    end try
  end tell
end safeName

on safeDescription(guiElement)
  tell application "System Events"
    try
      set currentValue to description of guiElement
      if currentValue is missing value then return ""
      return my boundedText(currentValue as text, 240)
    on error
      return ""
    end try
  end tell
end safeDescription

on safeValue(guiElement)
  tell application "System Events"
    try
      set currentValue to value of guiElement
      if currentValue is missing value then return ""
      return my boundedText(currentValue as text, 240)
    on error
      return ""
    end try
  end tell
end safeValue

on safeEnabled(guiElement)
  tell application "System Events"
    try
      return enabled of guiElement as boolean
    on error
      return missing value
    end try
  end tell
end safeEnabled

on safeFocused(guiElement)
  tell application "System Events"
    try
      return focused of guiElement as boolean
    on error
      return false
    end try
  end tell
end safeFocused

on safeBundleIdentifier(guiProcess)
  tell application "System Events"
    try
      return bundle identifier of guiProcess as text
    on error
      return ""
    end try
  end tell
end safeBundleIdentifier

on safeActions(guiElement)
  set names to {}
  tell application "System Events"
    try
      repeat with actionReference in actions of guiElement
        try
          set end of names to name of actionReference as text
        end try
      end repeat
    end try
  end tell
  return names
end safeActions

on safePair(guiElement, pairName)
  tell application "System Events"
    try
      if pairName is "position" then
        set pairValue to position of guiElement
      else
        set pairValue to size of guiElement
      end if
      return "[" & (item 1 of pairValue as integer) & "," & (item 2 of pairValue as integer) & "]"
    on error
      return "null"
    end try
  end tell
end safePair

on modifierList(modifierText)
  set modifierKeys to {}
  if modifierText contains "command" then set end of modifierKeys to command down
  if modifierText contains "option" then set end of modifierKeys to option down
  if modifierText contains "control" then set end of modifierKeys to control down
  if modifierText contains "shift" then set end of modifierKeys to shift down
  return modifierKeys
end modifierList

on decodeBase64(encodedValue)
  if encodedValue is "" then return ""
  return do shell script "/usr/bin/printf %s " & quoted form of encodedValue & " | /usr/bin/base64 -D"
end decodeBase64

on boundedText(value, maximumLength)
  set textValue to value as text
  if (count of characters of textValue) > maximumLength then return text 1 thru maximumLength of textValue
  return textValue
end boundedText

on emitSuccess(payload)
  return resultMarker & "{\"ok\":true,\"data\":" & payload & "}"
end emitSuccess

on emitError(codeValue, messageValue)
  return resultMarker & "{\"ok\":false,\"code\":" & my jsonString(codeValue) & ",\"message\":" & my jsonString(messageValue) & "}"
end emitError

on jsonBoolean(value)
  if value then return "true"
  return "false"
end jsonBoolean

on jsonNullableBoolean(value)
  if value is missing value then return "null"
  return my jsonBoolean(value)
end jsonNullableBoolean

on jsonStringArray(valuesList)
  set encodedItems to {}
  repeat with currentValue in valuesList
    set end of encodedItems to my jsonString(currentValue as text)
  end repeat
  return my joinText(encodedItems, ",")
end jsonStringArray

on jsonString(value)
  if value is missing value then return "null"
  set escapedValue to value as text
  set escapedValue to my replaceText("\\", "\\\\", escapedValue)
  set escapedValue to my replaceText("\"", "\\\"", escapedValue)
  set escapedValue to my replaceText(return, "\\n", escapedValue)
  set escapedValue to my replaceText(linefeed, "\\n", escapedValue)
  set escapedValue to my replaceText(tab, "\\t", escapedValue)
  return "\"" & escapedValue & "\""
end jsonString

on replaceText(findText, replacementText, sourceText)
  set previousDelimiters to AppleScript's text item delimiters
  set AppleScript's text item delimiters to findText
  set textItems to text items of sourceText
  set AppleScript's text item delimiters to replacementText
  set resultText to textItems as text
  set AppleScript's text item delimiters to previousDelimiters
  return resultText
end replaceText

on joinText(valuesList, delimiterText)
  if (count of valuesList) is 0 then return ""
  set previousDelimiters to AppleScript's text item delimiters
  set AppleScript's text item delimiters to delimiterText
  set resultText to valuesList as text
  set AppleScript's text item delimiters to previousDelimiters
  return resultText
end joinText
`;
