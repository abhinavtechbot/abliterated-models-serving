#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <dlfcn.h>
#include <stdio.h>

typedef CFDictionaryRef (*IOReportCopyChannelsInGroup_t)(CFStringRef, CFStringRef, uint64_t, uint64_t, uint64_t);
typedef CFDictionaryRef (*IOReportCreateSubscription_t)(void*, CFMutableDictionaryRef, CFMutableDictionaryRef*, uint64_t, CFTypeRef);
typedef CFDictionaryRef (*IOReportCreateSamples_t)(void*, CFMutableDictionaryRef, CFTypeRef);
typedef int (*IOReportIterate_t)(CFDictionaryRef, int (^)(id));
typedef CFStringRef (*IOReportChannelGetChannelName_t)(id);
typedef CFStringRef (*IOReportChannelGetDriverName_t)(id);
typedef int64_t (*IOReportSimpleGetIntegerValue_t)(id, int);

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSMutableDictionary *gpus = [NSMutableDictionary dictionary];

        // 1. Query Metal device memory & working set size (non-blocking via MTLCopyAllDevices)
        NSArray<id<MTLDevice>> *mtlDevs = MTLCopyAllDevices();
        for (id<MTLDevice> d in mtlDevs) {
            NSString *name = [d name] ?: @"GPU";
            NSString *key = ([name containsString:@"AMD"] || [name containsString:@"Radeon"]) ? @"amd" : @"intel";
            uint64_t allocBytes = (uint64_t)[d currentAllocatedSize];
            uint64_t maxBytes = (uint64_t)[d recommendedMaxWorkingSetSize];
            gpus[key] = [@{
                @"name": name,
                @"mtl_allocated_bytes": @(allocBytes),
                @"mtl_max_bytes": @(maxBytes),
                @"busy_ns": @(0ULL),
                @"total_ns": @(0ULL),
                @"busy_3d_ns": @(0ULL),
                @"busy_compute_ns": @(0ULL),
                @"busy_dma_ns": @(0ULL),
                @"in_use_vid_bytes": @(0ULL),
                @"in_use_sys_bytes": @(0ULL)
            } mutableCopy];
        }

        // 2. Query libIOReport Internal Statistics for hardware GPU busy counters and VRAM
        void *h = dlopen("/usr/lib/libIOReport.dylib", RTLD_NOW);
        if (h) {
            IOReportCopyChannelsInGroup_t copyGroup = dlsym(h, "IOReportCopyChannelsInGroup");
            IOReportCreateSubscription_t createSub = dlsym(h, "IOReportCreateSubscription");
            IOReportCreateSamples_t createSamples = dlsym(h, "IOReportCreateSamples");
            IOReportIterate_t iterate = dlsym(h, "IOReportIterate");
            IOReportChannelGetChannelName_t getName = dlsym(h, "IOReportChannelGetChannelName");
            IOReportChannelGetDriverName_t getDriver = dlsym(h, "IOReportChannelGetDriverName");
            IOReportSimpleGetIntegerValue_t getInt = dlsym(h, "IOReportSimpleGetIntegerValue");

            if (copyGroup && createSub && createSamples && iterate && getName && getDriver && getInt) {
                CFDictionaryRef ch = copyGroup(CFSTR("Internal Statistics"), NULL, 0, 0, 0);
                if (ch) {
                    CFMutableDictionaryRef mch = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, ch);
                    CFMutableDictionaryRef subch = NULL;
                    void *sub = (void*)createSub(NULL, mch, &subch, 0, NULL);
                    if (sub && subch) {
                        CFDictionaryRef s1 = createSamples(sub, subch, NULL);
                        if (s1) {
                            iterate(s1, ^int(id item) {
                                NSString *drv = (__bridge NSString*)getDriver(item) ?: @"";
                                NSString *chName = (__bridge NSString*)getName(item) ?: @"";
                                int64_t val = getInt(item, 0);
                                if (val < 0) val = 0;

                                NSString *key = nil;
                                if ([drv containsString:@"AMD"] || [drv containsString:@"Radeon"]) {
                                    key = @"amd";
                                } else if ([drv containsString:@"Intel"]) {
                                    key = @"intel";
                                }
                                if (!key) return 0;

                                NSMutableDictionary *entry = gpus[key];
                                if (!entry) {
                                    entry = [@{
                                        @"name": ([key isEqualToString:@"amd"] ? @"AMD Radeon Pro 560" : @"Intel HD Graphics 630"),
                                        @"mtl_allocated_bytes": @(0ULL),
                                        @"mtl_max_bytes": @([key isEqualToString:@"amd"] ? 4294967296ULL : 1610612736ULL),
                                        @"busy_ns": @(0ULL),
                                        @"total_ns": @(0ULL),
                                        @"busy_3d_ns": @(0ULL),
                                        @"busy_compute_ns": @(0ULL),
                                        @"busy_dma_ns": @(0ULL),
                                        @"in_use_vid_bytes": @(0ULL),
                                        @"in_use_sys_bytes": @(0ULL)
                                    } mutableCopy];
                                    gpus[key] = entry;
                                }

                                if ([chName isEqualToString:@"Overall GPU Busy"]) {
                                    entry[@"busy_ns"] = @(MAX([entry[@"busy_ns"] unsignedLongLongValue], (uint64_t)val));
                                } else if ([chName isEqualToString:@"Overall GPU total time"]) {
                                    entry[@"total_ns"] = @(MAX([entry[@"total_ns"] unsignedLongLongValue], (uint64_t)val));
                                } else if ([chName isEqualToString:@"3d Busy"]) {
                                    entry[@"busy_3d_ns"] = @(MAX([entry[@"busy_3d_ns"] unsignedLongLongValue], (uint64_t)val));
                                } else if ([chName isEqualToString:@"Compute Busy"]) {
                                    entry[@"busy_compute_ns"] = @(MAX([entry[@"busy_compute_ns"] unsignedLongLongValue], (uint64_t)val));
                                } else if ([chName isEqualToString:@"DMA Busy"]) {
                                    entry[@"busy_dma_ns"] = @(MAX([entry[@"busy_dma_ns"] unsignedLongLongValue], (uint64_t)val));
                                } else if ([chName isEqualToString:@"In use video memory"]) {
                                    entry[@"in_use_vid_bytes"] = @(MAX([entry[@"in_use_vid_bytes"] unsignedLongLongValue], (uint64_t)val));
                                } else if ([chName isEqualToString:@"In use system memory"]) {
                                    entry[@"in_use_sys_bytes"] = @(MAX([entry[@"in_use_sys_bytes"] unsignedLongLongValue], (uint64_t)val));
                                }
                                return 0;
                            });
                            CFRelease(s1);
                        }
                    }
                    if (subch) CFRelease(subch);
                    if (mch) CFRelease(mch);
                    CFRelease(ch);
                }
            }
        }

        NSDictionary *out = @{@"ok": @YES, @"gpus": gpus};
        NSData *json = [NSJSONSerialization dataWithJSONObject:out options:0 error:nil];
        if (json) {
            fwrite([json bytes], 1, [json length], stdout);
            printf("\n");
        } else {
            printf("{\"ok\":false}\n");
        }
    }
    return 0;
}
