#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>

@interface DevSpaceGuiFixtureDelegate : NSObject <NSApplicationDelegate>
@property(nonatomic, strong) NSWindow *window;
@property(nonatomic, strong) NSTextField *input;
@property(nonatomic, strong) NSTextField *status;
@property(nonatomic, copy) NSString *statePath;
@end

@implementation DevSpaceGuiFixtureDelegate

- (void)writeState:(NSString *)state applied:(BOOL)applied {
  NSDictionary *value = @{
    @"state": state,
    @"value": self.input.stringValue ?: @"",
    @"applied": @(applied),
    @"pid": @([[NSProcessInfo processInfo] processIdentifier]),
    @"bundleIdentifier": [[NSBundle mainBundle] bundleIdentifier] ?: @"com.devspace.gui-fixture",
  };
  NSError *error = nil;
  NSData *json = [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingPrettyPrinted error:&error];
  if (json == nil || ![json writeToFile:self.statePath options:NSDataWritingAtomic error:&error]) {
    NSLog(@"Fixture state write failed: %@", error);
  }
}

- (void)applyValue:(id)sender {
  (void)sender;
  self.status.stringValue = [NSString stringWithFormat:@"Applied: %@", self.input.stringValue ?: @""];
  [self writeState:@"APPLIED" applied:YES];
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
  (void)notification;
  NSArray<NSString *> *arguments = [[NSProcessInfo processInfo] arguments];
  if (arguments.count < 2 || ![arguments[1] hasPrefix:@"/"]) {
    [NSApp terminate:nil];
    return;
  }
  self.statePath = arguments[1];
  NSRect frame = NSMakeRect(0, 0, 520, 260);
  self.window = [[NSWindow alloc] initWithContentRect:frame
                                            styleMask:(NSWindowStyleMaskTitled
                                                       | NSWindowStyleMaskClosable
                                                       | NSWindowStyleMaskMiniaturizable)
                                              backing:NSBackingStoreBuffered
                                                defer:NO];
  self.window.title = @"DevSpace GUI Fixture";
  [self.window center];

  NSTextField *heading = [[NSTextField alloc] initWithFrame:NSMakeRect(40, 190, 440, 28)];
  heading.bezeled = NO;
  heading.drawsBackground = NO;
  heading.editable = NO;
  heading.selectable = NO;
  heading.stringValue = @"DevSpace actual Accessibility fixture";
  heading.accessibilityLabel = @"DevSpace Fixture Heading";

  self.input = [[NSTextField alloc] initWithFrame:NSMakeRect(40, 135, 300, 32)];
  self.input.stringValue = @"before";
  self.input.placeholderString = @"Enter fixture value";
  self.input.accessibilityLabel = @"DevSpace Input";
  self.input.identifier = @"devspace-input";

  NSButton *button = [[NSButton alloc] initWithFrame:NSMakeRect(360, 135, 120, 32)];
  button.title = @"Apply";
  button.bezelStyle = NSBezelStyleRounded;
  button.target = self;
  button.action = @selector(applyValue:);
  button.accessibilityLabel = @"Apply";
  button.identifier = @"devspace-apply";

  self.status = [[NSTextField alloc] initWithFrame:NSMakeRect(40, 75, 440, 28)];
  self.status.bezeled = NO;
  self.status.drawsBackground = NO;
  self.status.editable = NO;
  self.status.selectable = YES;
  self.status.stringValue = @"Not applied";
  self.status.accessibilityLabel = @"DevSpace Status";
  self.status.identifier = @"devspace-status";

  NSView *content = self.window.contentView;
  [content addSubview:heading];
  [content addSubview:self.input];
  [content addSubview:button];
  [content addSubview:self.status];
  [self.window makeKeyAndOrderFront:nil];
  [NSApp activateIgnoringOtherApps:YES];
  [self.input becomeFirstResponder];
  [self writeState:@"READY" applied:NO];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
  (void)sender;
  return YES;
}
@end

int main(int argc, const char *argv[]) {
  (void)argc;
  (void)argv;
  @autoreleasepool {
    NSApplication *application = [NSApplication sharedApplication];
    application.activationPolicy = NSApplicationActivationPolicyRegular;
    DevSpaceGuiFixtureDelegate *delegate = [DevSpaceGuiFixtureDelegate new];
    application.delegate = delegate;
    [application run];
  }
  return 0;
}
