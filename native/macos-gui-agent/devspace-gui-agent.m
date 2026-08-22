#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#import <CoreServices/CoreServices.h>
#import <CommonCrypto/CommonDigest.h>

static NSString * const DevSpaceMarker = @"__DEVSPACE_V2_GUI_JSON__";
static NSString * const DevSpaceBundleIdentifier = @"com.devspace.gui-agent";
static const NSUInteger DevSpaceMaximumTraversal = 5000;
static const NSUInteger DevSpaceMaximumDepth = 16;

static NSString *boundedString(id value, NSUInteger maximum) {
  if (value == nil || value == [NSNull null]) return @"";
  NSString *text;
  if ([value isKindOfClass:[NSString class]]) text = value;
  else if ([value isKindOfClass:[NSNumber class]]) text = [value stringValue];
  else text = [value description] ?: @"";
  text = [text stringByReplacingOccurrencesOfString:@"\0" withString:@""];
  if (text.length > maximum) return [text substringToIndex:maximum];
  return text;
}

static int emitResult(BOOL ok, NSDictionary *data, NSString *code, NSString *message) {
  NSMutableDictionary *payload = [NSMutableDictionary dictionaryWithObject:@(ok) forKey:@"ok"];
  if (data != nil) payload[@"data"] = data;
  if (code != nil) payload[@"code"] = code;
  if (message != nil) payload[@"message"] = boundedString(message, 1000);
  NSError *error = nil;
  NSData *json = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&error];
  if (json == nil) {
    fprintf(stderr, "GUI agent JSON serialization failed: %s\n", error.localizedDescription.UTF8String);
    return 70;
  }
  NSString *line = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
  fprintf(stdout, "%s%s\n", DevSpaceMarker.UTF8String, line.UTF8String);
  fflush(stdout);
  return 0;
}

static id copyAttribute(AXUIElementRef element, CFStringRef attribute) {
  CFTypeRef value = NULL;
  AXError status = AXUIElementCopyAttributeValue(element, attribute, &value);
  if (status != kAXErrorSuccess || value == NULL) return nil;
  return CFBridgingRelease(value);
}

static NSString *stringAttribute(AXUIElementRef element, CFStringRef attribute) {
  return boundedString(copyAttribute(element, attribute), 240);
}

static NSNumber *booleanAttribute(AXUIElementRef element, CFStringRef attribute) {
  id value = copyAttribute(element, attribute);
  return [value isKindOfClass:[NSNumber class]] ? value : nil;
}

static id pointOrSize(id value, BOOL size) {
  if (value == nil || CFGetTypeID((__bridge CFTypeRef)value) != AXValueGetTypeID()) return [NSNull null];
  AXValueRef axValue = (__bridge AXValueRef)value;
  if (size) {
    CGSize result = CGSizeZero;
    if (!AXValueGetValue(axValue, kAXValueCGSizeType, &result)) return [NSNull null];
    return @[@(result.width), @(result.height)];
  }
  CGPoint result = CGPointZero;
  if (!AXValueGetValue(axValue, kAXValueCGPointType, &result)) return [NSNull null];
  return @[@(result.x), @(result.y)];
}

static NSArray<NSString *> *actionsForElement(AXUIElementRef element) {
  CFArrayRef actions = NULL;
  if (AXUIElementCopyActionNames(element, &actions) != kAXErrorSuccess || actions == NULL) return @[];
  NSArray *bridged = CFBridgingRelease(actions);
  NSMutableArray<NSString *> *result = [NSMutableArray array];
  for (id value in bridged) {
    if (![value isKindOfClass:[NSString class]]) continue;
    [result addObject:boundedString(value, 120)];
    if (result.count >= 32) break;
  }
  return result;
}

static NSString *sha256Text(NSString *text) {
  NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
  NSMutableString *hex = [NSMutableString stringWithCapacity:64];
  for (NSUInteger index = 0; index < CC_SHA256_DIGEST_LENGTH; index += 1) {
    [hex appendFormat:@"%02x", digest[index]];
  }
  return [@"sha256:" stringByAppendingString:hex];
}

static NSDictionary *elementDescriptor(AXUIElementRef element, NSUInteger index) {
  NSString *role = stringAttribute(element, kAXRoleAttribute);
  NSString *subrole = stringAttribute(element, kAXSubroleAttribute);
  NSString *name = stringAttribute(element, kAXTitleAttribute);
  if (name.length == 0) name = stringAttribute(element, kAXIdentifierAttribute);
  NSString *description = stringAttribute(element, kAXDescriptionAttribute);
  NSString *value = stringAttribute(element, kAXValueAttribute);
  NSNumber *enabled = booleanAttribute(element, kAXEnabledAttribute);
  NSNumber *focused = booleanAttribute(element, kAXFocusedAttribute);
  NSString *identity = [NSString stringWithFormat:@"%lu\0%@\0%@\0%@\0%@",
                        (unsigned long)index, role, subrole, name, description];
  NSString *digest = sha256Text(identity);
  NSString *elementId = [NSString stringWithFormat:@"e%lu-%@",
                         (unsigned long)index,
                         [digest substringWithRange:NSMakeRange(7, 12)]];
  return @{
    @"elementId": elementId,
    @"index": @(index),
    @"role": role,
    @"subrole": subrole,
    @"name": name,
    @"description": description,
    @"value": value,
    @"enabled": enabled ?: [NSNull null],
    @"focused": focused ?: @NO,
    @"position": pointOrSize(copyAttribute(element, kAXPositionAttribute), NO),
    @"size": pointOrSize(copyAttribute(element, kAXSizeAttribute), YES),
    @"actions": actionsForElement(element),
  };
}

@interface DevSpaceTraversal : NSObject
@property(nonatomic) NSUInteger maximum;
@property(nonatomic) NSUInteger visited;
@property(nonatomic) BOOL truncated;
@property(nonatomic, strong) NSMutableArray<NSDictionary *> *elements;
@property(nonatomic, strong) NSMutableArray *references;
@end
@implementation DevSpaceTraversal
@end

static void collectElements(AXUIElementRef element, DevSpaceTraversal *context, NSUInteger depth) {
  if (element == NULL || depth > DevSpaceMaximumDepth || context.visited >= DevSpaceMaximumTraversal) {
    context.truncated = YES;
    return;
  }
  NSUInteger index = context.visited;
  context.visited += 1;
  if (context.elements.count < context.maximum) {
    [context.elements addObject:elementDescriptor(element, index)];
    [context.references addObject:(__bridge_transfer id)CFRetain(element)];
  } else {
    context.truncated = YES;
    return;
  }
  id children = copyAttribute(element, kAXChildrenAttribute);
  if (![children isKindOfClass:[NSArray class]]) return;
  for (id child in (NSArray *)children) {
    if (CFGetTypeID((__bridge CFTypeRef)child) != AXUIElementGetTypeID()) continue;
    collectElements((__bridge AXUIElementRef)child, context, depth + 1);
    if (context.elements.count >= context.maximum || context.visited >= DevSpaceMaximumTraversal) {
      context.truncated = YES;
      break;
    }
  }
}

static AXUIElementRef focusedWindow(AXUIElementRef application) {
  id focused = copyAttribute(application, kAXFocusedWindowAttribute);
  if (focused != nil && CFGetTypeID((__bridge CFTypeRef)focused) == AXUIElementGetTypeID()) {
    return (__bridge_retained AXUIElementRef)focused;
  }
  id windows = copyAttribute(application, kAXWindowsAttribute);
  if ([windows isKindOfClass:[NSArray class]] && [(NSArray *)windows count] > 0) {
    id first = [(NSArray *)windows firstObject];
    if (CFGetTypeID((__bridge CFTypeRef)first) == AXUIElementGetTypeID()) {
      return (__bridge_retained AXUIElementRef)first;
    }
  }
  return NULL;
}

static NSRunningApplication *frontmostApplication(void) {
  NSRunningApplication *frontmost = NSWorkspace.sharedWorkspace.frontmostApplication;
  if (frontmost != nil && ![frontmost.bundleIdentifier isEqualToString:DevSpaceBundleIdentifier]) return frontmost;
  for (NSRunningApplication *candidate in NSWorkspace.sharedWorkspace.runningApplications) {
    if (candidate.activationPolicy == NSApplicationActivationPolicyRegular
        && ![candidate.bundleIdentifier isEqualToString:DevSpaceBundleIdentifier]
        && !candidate.terminated) return candidate;
  }
  return nil;
}

static NSDictionary *observeApplication(pid_t requestedPid, NSUInteger maximum, NSMutableArray **referencesOut) {
  if (!AXIsProcessTrusted()) return nil;
  NSRunningApplication *application = requestedPid > 0
    ? [NSRunningApplication runningApplicationWithProcessIdentifier:requestedPid]
    : frontmostApplication();
  if (application == nil) return nil;
  AXUIElementRef appElement = AXUIElementCreateApplication(application.processIdentifier);
  if (appElement == NULL) return nil;
  AXUIElementRef window = focusedWindow(appElement);
  DevSpaceTraversal *traversal = [DevSpaceTraversal new];
  traversal.maximum = MAX((NSUInteger)1, MIN(maximum, (NSUInteger)1000));
  traversal.elements = [NSMutableArray array];
  traversal.references = [NSMutableArray array];
  traversal.visited = 0;
  traversal.truncated = NO;
  collectElements(window != NULL ? window : appElement, traversal, 0);

  NSDictionary *windowValue = window == NULL ? (id)[NSNull null] : @{
    @"title": stringAttribute(window, kAXTitleAttribute),
    @"role": stringAttribute(window, kAXRoleAttribute),
    @"subrole": stringAttribute(window, kAXSubroleAttribute),
    @"position": pointOrSize(copyAttribute(window, kAXPositionAttribute), NO),
    @"size": pointOrSize(copyAttribute(window, kAXSizeAttribute), YES),
  };
  NSDictionary *result = @{
    @"application": @{
      @"name": boundedString(application.localizedName, 240),
      @"bundleIdentifier": boundedString(application.bundleIdentifier, 240),
      @"pid": @(application.processIdentifier),
    },
    @"window": windowValue,
    @"elements": traversal.elements,
    @"totalElements": @(traversal.visited),
    @"omittedElements": @(traversal.visited > traversal.elements.count
                          ? traversal.visited - traversal.elements.count : 0),
    @"truncated": @(traversal.truncated),
  };
  if (referencesOut != NULL) *referencesOut = traversal.references;
  if (window != NULL) CFRelease(window);
  CFRelease(appElement);
  return result;
}

static NSString *decodeBase64(const char *value) {
  if (value == NULL) return nil;
  NSString *text = [NSString stringWithUTF8String:value];
  NSData *data = [[NSData alloc] initWithBase64EncodedString:text options:0];
  if (data == nil || data.length > 16384) return nil;
  return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static BOOL parseInteger(const char *value, NSInteger minimum, NSInteger maximum, NSInteger *output) {
  if (value == NULL || *value == '\0') return NO;
  char *end = NULL;
  long long parsed = strtoll(value, &end, 10);
  if (end == value || *end != '\0' || parsed < minimum || parsed > maximum) return NO;
  *output = (NSInteger)parsed;
  return YES;
}

static CGEventFlags flagsFromModifiers(NSString *value) {
  CGEventFlags flags = 0;
  for (NSString *modifier in [value componentsSeparatedByString:@","]) {
    if ([modifier isEqualToString:@"command"]) flags |= kCGEventFlagMaskCommand;
    else if ([modifier isEqualToString:@"option"]) flags |= kCGEventFlagMaskAlternate;
    else if ([modifier isEqualToString:@"control"]) flags |= kCGEventFlagMaskControl;
    else if ([modifier isEqualToString:@"shift"]) flags |= kCGEventFlagMaskShift;
  }
  return flags;
}

static BOOL postUnicodeText(NSString *text, CGEventFlags flags) {
  if (text.length > 1024) return NO;
  UniChar *characters = calloc(MAX(text.length, (NSUInteger)1), sizeof(UniChar));
  if (characters == NULL) return NO;
  [text getCharacters:characters range:NSMakeRange(0, text.length)];
  CGEventRef down = CGEventCreateKeyboardEvent(NULL, 0, true);
  CGEventRef up = CGEventCreateKeyboardEvent(NULL, 0, false);
  if (down == NULL || up == NULL) {
    if (down != NULL) CFRelease(down);
    if (up != NULL) CFRelease(up);
    free(characters);
    return NO;
  }
  CGEventSetFlags(down, flags);
  CGEventSetFlags(up, flags);
  CGEventKeyboardSetUnicodeString(down, text.length, characters);
  CGEventKeyboardSetUnicodeString(up, 0, NULL);
  CGEventPost(kCGHIDEventTap, down);
  CGEventPost(kCGHIDEventTap, up);
  CFRelease(down);
  CFRelease(up);
  free(characters);
  return YES;
}

static BOOL postKeyCode(CGKeyCode keyCode, CGEventFlags flags) {
  CGEventRef down = CGEventCreateKeyboardEvent(NULL, keyCode, true);
  CGEventRef up = CGEventCreateKeyboardEvent(NULL, keyCode, false);
  if (down == NULL || up == NULL) {
    if (down != NULL) CFRelease(down);
    if (up != NULL) CFRelease(up);
    return NO;
  }
  CGEventSetFlags(down, flags);
  CGEventSetFlags(up, flags);
  CGEventPost(kCGHIDEventTap, down);
  CGEventPost(kCGHIDEventTap, up);
  CFRelease(down);
  CFRelease(up);
  return YES;
}

static BOOL expectedMatches(NSDictionary *descriptor, NSString *windowTitle,
                            NSString *role, NSString *subrole,
                            NSString *name, NSString *description) {
  BOOL windowMatches = windowTitle.length == 0 || [windowTitle isEqualToString:descriptor[@"windowTitle"] ?: @""];
  return windowMatches
    && [role isEqualToString:descriptor[@"role"] ?: @""]
    && [subrole isEqualToString:descriptor[@"subrole"] ?: @""]
    && [name isEqualToString:descriptor[@"name"] ?: @""]
    && [description isEqualToString:descriptor[@"description"] ?: @""];
}

static int handleAct(int argc, const char *argv[]) {
  if (argc != 13) return emitResult(NO, nil, @"INVALID_ARGUMENT", @"GUI act argument count is invalid.");
  NSInteger elementIndex = -1, keyCode = -1, pid = 0;
  if (!parseInteger(argv[1], -1, 1000, &elementIndex)
      || !parseInteger(argv[6], -1, 255, &keyCode)
      || !parseInteger(argv[7], 0, INT32_MAX, &pid)) {
    return emitResult(NO, nil, @"INVALID_ARGUMENT", @"GUI act numeric arguments are invalid.");
  }
  NSString *actionType = [NSString stringWithUTF8String:argv[2]];
  NSString *actionName = decodeBase64(argv[3]);
  NSString *value = decodeBase64(argv[4]);
  NSString *modifiers = [NSString stringWithUTF8String:argv[5]];
  NSString *windowTitle = decodeBase64(argv[8]);
  NSString *role = decodeBase64(argv[9]);
  NSString *name = decodeBase64(argv[10]);
  NSString *description = decodeBase64(argv[11]);
  NSString *subrole = decodeBase64(argv[12]);
  if (actionName == nil || value == nil || windowTitle == nil || role == nil
      || name == nil || description == nil || subrole == nil) {
    return emitResult(NO, nil, @"INVALID_ARGUMENT", @"GUI act encoded arguments are invalid.");
  }

  NSMutableArray *references = nil;
  NSDictionary *observation = observeApplication((pid_t)pid, MAX((NSInteger)1, elementIndex + 1), &references);
  if (observation == nil) return emitResult(NO, nil, @"CAPABILITY_UNAVAILABLE", @"Accessibility access is unavailable.");
  NSString *observedWindow = observation[@"window"] == [NSNull null] ? @"" : observation[@"window"][@"title"];
  if (windowTitle.length > 0 && ![windowTitle isEqualToString:observedWindow ?: @""]) {
    return emitResult(NO, nil, @"GUI_STATE_CHANGED", @"Focused window title changed.");
  }
  AXUIElementRef element = NULL;
  NSDictionary *descriptor = nil;
  if (elementIndex >= 0) {
    if ((NSUInteger)elementIndex >= references.count || (NSUInteger)elementIndex >= [observation[@"elements"] count]) {
      return emitResult(NO, nil, @"GUI_STATE_CHANGED", @"Observed element is no longer available.");
    }
    element = (__bridge AXUIElementRef)references[(NSUInteger)elementIndex];
    descriptor = observation[@"elements"][(NSUInteger)elementIndex];
    NSMutableDictionary *comparison = [descriptor mutableCopy];
    comparison[@"windowTitle"] = observedWindow ?: @"";
    if (!expectedMatches(comparison, windowTitle, role, subrole, name, description)) {
      return emitResult(NO, nil, @"GUI_STATE_CHANGED", @"Observed element fingerprint changed.");
    }
  }

  BOOL performed = NO;
  AXError axStatus = kAXErrorSuccess;
  CGEventFlags flags = flagsFromModifiers(modifiers);
  if ([actionType isEqualToString:@"perform"] && element != NULL && actionName.length > 0) {
    axStatus = AXUIElementPerformAction(element, (__bridge CFStringRef)actionName);
    performed = axStatus == kAXErrorSuccess;
  } else if (([actionType isEqualToString:@"press"] || [actionType isEqualToString:@"click"])
             && element != NULL) {
    axStatus = AXUIElementPerformAction(element, kAXPressAction);
    performed = axStatus == kAXErrorSuccess;
  } else if ([actionType isEqualToString:@"set_value"] && element != NULL) {
    axStatus = AXUIElementSetAttributeValue(element, kAXValueAttribute, (__bridge CFTypeRef)value);
    performed = axStatus == kAXErrorSuccess;
  } else if ([actionType isEqualToString:@"focus"] && element != NULL) {
    axStatus = AXUIElementSetAttributeValue(element, kAXFocusedAttribute, kCFBooleanTrue);
    performed = axStatus == kAXErrorSuccess;
  } else if ([actionType isEqualToString:@"keystroke"]) {
    performed = postUnicodeText(value, flags);
  } else if ([actionType isEqualToString:@"key_code"] && keyCode >= 0) {
    performed = postKeyCode((CGKeyCode)keyCode, flags);
  }
  if (!performed) {
    return emitResult(NO, nil, @"CAPABILITY_UNAVAILABLE",
                      [NSString stringWithFormat:@"GUI action failed (%d).", axStatus]);
  }
  return emitResult(YES, @{@"performed": @YES, @"actionType": actionType}, nil, nil);
}

static CGImageRef scaledImage(CGImageRef source, size_t maximumWidth) {
  size_t sourceWidth = CGImageGetWidth(source);
  size_t sourceHeight = CGImageGetHeight(source);
  if (sourceWidth <= maximumWidth) return CGImageRetain(source);
  CGFloat ratio = (CGFloat)maximumWidth / (CGFloat)sourceWidth;
  size_t width = maximumWidth;
  size_t height = MAX((size_t)1, (size_t)llround((CGFloat)sourceHeight * ratio));
  CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
  CGContextRef context = CGBitmapContextCreate(NULL, width, height, 8, width * 4,
                                               colorSpace,
                                               kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
  CGColorSpaceRelease(colorSpace);
  if (context == NULL) return NULL;
  CGContextSetInterpolationQuality(context, kCGInterpolationHigh);
  CGContextDrawImage(context, CGRectMake(0, 0, width, height), source);
  CGImageRef result = CGBitmapContextCreateImage(context);
  CGContextRelease(context);
  return result;
}

static NSString *sha256Data(NSData *data) {
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
  NSMutableString *hex = [NSMutableString stringWithString:@"sha256:"];
  for (NSUInteger index = 0; index < CC_SHA256_DIGEST_LENGTH; index += 1) {
    [hex appendFormat:@"%02x", digest[index]];
  }
  return hex;
}

static int handleCapture(NSString *format, NSInteger quality, NSInteger maximumWidth) {
  if (!CGPreflightScreenCaptureAccess()) {
    return emitResult(NO, nil, @"CAPABILITY_UNAVAILABLE", @"Screen Recording access is unavailable.");
  }
  CGImageRef source = CGWindowListCreateImage(CGRectInfinite,
                                               kCGWindowListOptionOnScreenOnly,
                                               kCGNullWindowID,
                                               kCGWindowImageDefault);
  if (source == NULL) return emitResult(NO, nil, @"CAPABILITY_UNAVAILABLE", @"Screen capture returned no image.");
  CGImageRef image = scaledImage(source, (size_t)maximumWidth);
  CGImageRelease(source);
  if (image == NULL) return emitResult(NO, nil, @"MCP_PROVIDER_ERROR", @"Screen capture scaling failed.");
  NSMutableData *data = [NSMutableData data];
  CFStringRef type = [format isEqualToString:@"png"] ? kUTTypePNG : kUTTypeJPEG;
  CGImageDestinationRef destination = CGImageDestinationCreateWithData((__bridge CFMutableDataRef)data,
                                                                       type, 1, NULL);
  if (destination == NULL) {
    CGImageRelease(image);
    return emitResult(NO, nil, @"MCP_PROVIDER_ERROR", @"Screen capture encoder is unavailable.");
  }
  NSDictionary *properties = [format isEqualToString:@"jpeg"]
    ? @{(__bridge NSString *)kCGImageDestinationLossyCompressionQuality: @((double)quality / 100.0)}
    : @{};
  CGImageDestinationAddImage(destination, image, (__bridge CFDictionaryRef)properties);
  BOOL finalized = CGImageDestinationFinalize(destination);
  CFRelease(destination);
  size_t width = CGImageGetWidth(image), height = CGImageGetHeight(image);
  CGImageRelease(image);
  if (!finalized || data.length == 0) return emitResult(NO, nil, @"MCP_PROVIDER_ERROR", @"Screen capture encoding failed.");
  if (data.length > 700000) return emitResult(NO, nil, @"RESOURCE_QUOTA_EXCEEDED", @"Screen capture exceeds the bounded protocol payload.");
  return emitResult(YES, @{
    @"contentBase64": [data base64EncodedStringWithOptions:0],
    @"mimeType": [format isEqualToString:@"png"] ? @"image/png" : @"image/jpeg",
    @"size": @(data.length),
    @"sha256": sha256Data(data),
    @"width": @(width),
    @"height": @(height),
  }, nil, nil);
}

static NSDictionary *capabilitiesPayload(void) {
  NSString *bundle = NSBundle.mainBundle.bundleIdentifier ?: DevSpaceBundleIdentifier;
  return @{
    @"platform": @"macos",
    @"bundleIdentifier": bundle,
    @"accessibility": @((BOOL)AXIsProcessTrusted()),
    @"screenCapture": @(CGPreflightScreenCaptureAccess()),
    @"protocol": @"devspace-macos-gui-v1",
  };
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    if (argc < 2) return emitResult(NO, nil, @"INVALID_ARGUMENT", @"GUI operation is required.");
    NSString *operation = [NSString stringWithUTF8String:argv[1]];
    if ([operation isEqualToString:@"capabilities"] && argc == 2) {
      return emitResult(YES, capabilitiesPayload(), nil, nil);
    }
    if ([operation isEqualToString:@"request-access"] && argc == 3) {
      NSString *permissions = [NSString stringWithUTF8String:argv[2]];
      BOOL requestAccessibility = [[permissions componentsSeparatedByString:@","] containsObject:@"accessibility"];
      BOOL requestCapture = [[permissions componentsSeparatedByString:@","] containsObject:@"screen_capture"];
      if (!requestAccessibility && !requestCapture) {
        return emitResult(NO, nil, @"INVALID_ARGUMENT", @"At least one known GUI permission is required.");
      }
      if (requestAccessibility) {
        NSDictionary *options = @{(__bridge NSString *)kAXTrustedCheckOptionPrompt: @YES};
        (void)AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
      }
      BOOL captureDecision = requestCapture ? CGRequestScreenCaptureAccess() : CGPreflightScreenCaptureAccess();
      BOOL accessibility = AXIsProcessTrusted();
      BOOL screenCapture = CGPreflightScreenCaptureAccess() || captureDecision;
      return emitResult(YES, @{
        @"requested": @{
          @"accessibility": @(requestAccessibility),
          @"screenCapture": @(requestCapture),
        },
        @"accessibility": @(accessibility),
        @"screenCapture": @(screenCapture),
        @"restartRequired": @((requestAccessibility && !accessibility) || (requestCapture && !screenCapture)),
      }, nil, nil);
    }
    if ([operation isEqualToString:@"observe"] && (argc == 3 || argc == 4)) {
      NSInteger maximum = 0;
      NSInteger requestedPid = 0;
      if (!parseInteger(argv[2], 1, 1000, &maximum)
          || (argc == 4 && !parseInteger(argv[3], 1, INT32_MAX, &requestedPid))) {
        return emitResult(NO, nil, @"INVALID_ARGUMENT", @"GUI observe maximum or process identifier is invalid.");
      }
      NSDictionary *observation = observeApplication((pid_t)requestedPid, (NSUInteger)maximum, NULL);
      if (observation == nil) {
        return emitResult(
          NO,
          nil,
          @"CAPABILITY_UNAVAILABLE",
          requestedPid > 0
            ? @"Accessibility access or the requested application process is unavailable."
            : @"Accessibility access or a foreground application is unavailable."
        );
      }
      return emitResult(YES, observation, nil, nil);
    }
    if ([operation isEqualToString:@"act"]) {
      return handleAct(argc - 1, argv + 1);
    }
    if ([operation isEqualToString:@"capture"] && argc == 5) {
      NSString *format = [NSString stringWithUTF8String:argv[2]];
      NSInteger quality = 0, maximumWidth = 0;
      if ((!([format isEqualToString:@"jpeg"] || [format isEqualToString:@"png"]))
          || !parseInteger(argv[3], 1, 100, &quality)
          || !parseInteger(argv[4], 320, 2560, &maximumWidth)) {
        return emitResult(NO, nil, @"INVALID_ARGUMENT", @"GUI capture arguments are invalid.");
      }
      return handleCapture(format, quality, maximumWidth);
    }
    return emitResult(NO, nil, @"INVALID_ARGUMENT", @"Unsupported GUI operation or argument shape.");
  }
}
