//go:build darwin && cgo

package keyring

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

static OSStatus shh_item_set(const char *service, const char *account, const char *group, const void *bytes, int len) {
    CFStringRef svc = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef acct = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFStringRef grp = CFStringCreateWithCString(NULL, group, kCFStringEncodingUTF8);
    CFDataRef data = CFDataCreate(NULL, bytes, (CFIndex)len);
    const void *keys[] = {
        kSecClass, kSecAttrService, kSecAttrAccount, kSecAttrAccessGroup,
        kSecAttrSynchronizable, kSecUseDataProtectionKeychain, kSecAttrAccessible, kSecValueData
    };
    const void *vals[] = {
        kSecClassGenericPassword, svc, acct, grp,
        kCFBooleanTrue, kCFBooleanTrue, kSecAttrAccessibleAfterFirstUnlock, data
    };
    CFDictionaryRef add = CFDictionaryCreate(NULL, keys, vals, 8, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    const void *dkeys[] = {
        kSecClass, kSecAttrService, kSecAttrAccount, kSecAttrAccessGroup,
        kSecAttrSynchronizable, kSecUseDataProtectionKeychain
    };
    const void *dvals[] = {
        kSecClassGenericPassword, svc, acct, grp, kCFBooleanTrue, kCFBooleanTrue
    };
    CFDictionaryRef del = CFDictionaryCreate(NULL, dkeys, dvals, 6, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    SecItemDelete(del);
    OSStatus st = SecItemAdd(add, NULL);
    CFRelease(add);
    CFRelease(del);
    CFRelease(data);
    CFRelease(svc);
    CFRelease(acct);
    CFRelease(grp);
    return st;
}

static OSStatus shh_item_get(const char *service, const char *account, const char *group, void *out, int outCap, int *outLen) {
    CFStringRef svc = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef acct = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFStringRef grp = CFStringCreateWithCString(NULL, group, kCFStringEncodingUTF8);
    const void *keys[] = {
        kSecClass, kSecAttrService, kSecAttrAccount, kSecAttrAccessGroup,
        kSecAttrSynchronizable, kSecUseDataProtectionKeychain, kSecReturnData, kSecMatchLimit
    };
    const void *vals[] = {
        kSecClassGenericPassword, svc, acct, grp,
        kCFBooleanTrue, kCFBooleanTrue, kCFBooleanTrue, kSecMatchLimitOne
    };
    CFDictionaryRef q = CFDictionaryCreate(NULL, keys, vals, 8, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef ref = NULL;
    OSStatus st = SecItemCopyMatching(q, &ref);
    CFRelease(q);
    CFRelease(svc);
    CFRelease(acct);
    CFRelease(grp);
    if (st != errSecSuccess) {
        return st;
    }
    if (CFGetTypeID(ref) != CFDataGetTypeID()) {
        CFRelease(ref);
        return errSecInternalComponent;
    }
    CFDataRef data = (CFDataRef)ref;
    int n = (int)CFDataGetLength(data);
    if (n > outCap) {
        CFRelease(ref);
        return errSecAllocate;
    }
    memcpy(out, CFDataGetBytePtr(data), (size_t)n);
    *outLen = n;
    CFRelease(ref);
    return errSecSuccess;
}

static OSStatus shh_item_delete(const char *service, const char *account, const char *group) {
    CFStringRef svc = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef acct = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFStringRef grp = CFStringCreateWithCString(NULL, group, kCFStringEncodingUTF8);
    const void *keys[] = {
        kSecClass, kSecAttrService, kSecAttrAccount, kSecAttrAccessGroup,
        kSecAttrSynchronizable, kSecUseDataProtectionKeychain
    };
    const void *vals[] = {
        kSecClassGenericPassword, svc, acct, grp, kCFBooleanTrue, kCFBooleanTrue
    };
    CFDictionaryRef del = CFDictionaryCreate(NULL, keys, vals, 6, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus st = SecItemDelete(del);
    CFRelease(del);
    CFRelease(svc);
    CFRelease(acct);
    CFRelease(grp);
    return st;
}
*/
import "C"
import "unsafe"

func syncGet(service, account string) (string, error) {
	buf := make([]byte, 4096)
	var n C.int
	st := callGet(service, account, syncAccessGroup, buf, &n)
	if err := syncStatus(int32(st)); err != nil {
		return "", err
	}
	if n < 0 || int(n) > len(buf) {
		return "", syncStatus(-1)
	}
	return string(buf[:int(n)]), nil
}

func syncSet(service, account, secret string) error {
	if len(secret) == 0 || len(secret) > 4096 {
		return syncStatus(-1)
	}
	return syncStatus(int32(callSet(service, account, syncAccessGroup, []byte(secret))))
}

func syncDelete(service, account string) error {
	return syncStatus(int32(callDelete(service, account, syncAccessGroup)))
}

func callGet(service, account, group string, buf []byte, n *C.int) C.OSStatus {
	cs, ca, cg := C.CString(service), C.CString(account), C.CString(group)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	defer C.free(unsafe.Pointer(cg))
	return C.shh_item_get(cs, ca, cg, unsafe.Pointer(&buf[0]), C.int(len(buf)), n)
}

func callSet(service, account, group string, secret []byte) C.OSStatus {
	cs, ca, cg := C.CString(service), C.CString(account), C.CString(group)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	defer C.free(unsafe.Pointer(cg))
	return C.shh_item_set(cs, ca, cg, unsafe.Pointer(&secret[0]), C.int(len(secret)))
}

func callDelete(service, account, group string) C.OSStatus {
	cs, ca, cg := C.CString(service), C.CString(account), C.CString(group)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	defer C.free(unsafe.Pointer(cg))
	return C.shh_item_delete(cs, ca, cg)
}
