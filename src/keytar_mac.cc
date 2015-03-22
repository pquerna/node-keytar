#include "keytar.h"

#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>

namespace keytar {

bool AddPassword(const std::string& service,
                 const std::string& account,
                 const std::string& password) {
  OSStatus status = SecKeychainAddGenericPassword(NULL,
                                                  service.length(),
                                                  service.data(),
                                                  account.length(),
                                                  account.data(),
                                                  password.length(),
                                                  password.data(),
                                                  NULL);
  return status == errSecSuccess;
}

bool GetPassword(const std::string& service,
                 const std::string& account,
                 std::string* password) {
  void *data;
  UInt32 length;
  OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                  service.length(),
                                                  service.data(),
                                                  account.length(),
                                                  account.data(),
                                                  &length,
                                                  &data,
                                                  NULL);
  if (status != errSecSuccess)
    return false;

  *password = std::string(reinterpret_cast<const char*>(data), length);
  SecKeychainItemFreeContent(NULL, data);
  return true;
}

bool DeletePassword(const std::string& service, const std::string& account) {
  SecKeychainItemRef item;
  OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                   service.length(),
                                                   service.data(),
                                                   account.length(),
                                                   account.data(),
                                                   NULL,
                                                   NULL,
                                                   &item);
  if (status != errSecSuccess)
    return false;

  status = SecKeychainItemDelete(item);
  CFRelease(item);
  return status == errSecSuccess;
}

bool FindPassword(const std::string& service, std::string* password) {
  SecKeychainItemRef item;
  void *data;
  UInt32 length;

  OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                   service.length(),
                                                   service.data(),
                                                   0,
                                                   NULL,
                                                   &length,
                                                   &data,
                                                   &item);
  if (status != errSecSuccess)
    return false;

  *password = std::string(reinterpret_cast<const char*>(data), length);
  SecKeychainItemFreeContent(NULL, data);
  CFRelease(item);
  return true;
}

char *cfstr(CFStringRef str) {
  if (str == NULL) {
    return NULL;
  }

  CFIndex length = CFStringGetLength(str);
  CFIndex encodedLen =
      CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8);
  char *buf = reinterpret_cast<char*>(malloc(encodedLen + 1));
  Boolean rv =
      CFStringGetCString(str, buf, encodedLen + 1, kCFStringEncodingUTF8);
  if (rv) {
    return buf;
  }
  return NULL;
}

char *secmsg(OSStatus err) {
  CFStringRef estr = SecCopyErrorMessageString(err, NULL);
  char *emsg = cfstr(estr);
  CFRelease(estr);
  return emsg;
}

// TODO(pquerna): return errors, don't print them :(
void secerr(const char *func, OSStatus err) {
  char* msg = secmsg(err);
  fprintf(stderr, "%s failed: (%d)%s\n", func, err, msg);
  free(reinterpret_cast<void*>(msg));
}

bool AddKeypair(const std::string& label,
        const std::string& certificate,
        const std::string& privateKey) {
  bool rv = false;
  OSStatus err;
  CFArrayRef items = NULL;
  SecKeychainRef importKeychain = NULL;
  CFStringRef labelStr = NULL;
  SecKeyRef key = NULL;
  SecCertificateRef cert = NULL;

  CFMutableDataRef data = NULL;
  SecKeychainAttribute attributes[1];
  SecKeychainAttributeList list;

  SecExternalItemType type = kSecItemTypeAggregate;
  SecExternalFormat format = kSecFormatPEMSequence;
  SecItemImportExportKeyParameters keyParams;

  err = SecKeychainCopyDefault(&importKeychain);
  if (err != noErr) {
    secerr("SecKeychainCopyDefault", err);
    goto cleanup;
  }

  memset(&keyParams, 0, sizeof(SecItemImportExportKeyParameters));
  keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;

  labelStr = CFStringCreateWithBytes(
    kCFAllocatorDefault,
    reinterpret_cast<const UInt8*>(label.data()),
    label.length() * sizeof(std::string::value_type),
    kCFStringEncodingUTF8, false);

  // TODO(pquerna): add SecTrustedApplicationCreateFromPath
  // for Chome/Firefox, etc?
  err = SecAccessCreate(labelStr, NULL, &keyParams.accessRef);
  if (err != noErr) {
    secerr("SecAccessCreate for label", err);
    goto cleanup;
  }

  data = CFDataCreateMutable(NULL, 0);
  CFDataAppendBytes(data,
    reinterpret_cast<const UInt8 *>(certificate.data()),
    certificate.length() * sizeof(std::string::value_type));
  CFDataAppendBytes(data,
    reinterpret_cast<const UInt8 *>(privateKey.data()),
    privateKey.length() * sizeof(std::string::value_type));

  err = SecItemImport((CFDataRef)data, CFSTR(".pem"), &format, &type, 0,
                     &keyParams, importKeychain, &items);

  CFRelease(data);
  data = NULL;

  if (err == errSecDuplicateItem) {
    // already loaded.
    // TODO(pquerna): better error handling (?)
    secerr("SecItemImport: errSecDuplicateItem", err);
    goto cleanup;
  }

  if (err != noErr) {
    secerr("SecItemImport", err);
    goto cleanup;
  }

// TODO(pquerna): is this a valid edge case?
/*
  if (CFArrayGetCount(items) != 2) {
    err = ac__error_createf(
        AC_ERR_MAC_KEYCHAIN_OPEN,
        "cred-store: SecItemImport imported more than expected items (%ld)",
        CFArrayGetCount(items));
    goto cleanup;
  }
  */

  for (CFIndex i = 0; i < CFArrayGetCount(items); i++) {
    CFTypeRef item =
      reinterpret_cast<CFTypeRef>(CFArrayGetValueAtIndex(items, i));
    CFTypeID itemType = CFGetTypeID(item);

    if (itemType == SecCertificateGetTypeID()) {
      cert = (SecCertificateRef)item;
      CFRetain(cert);
    } else if (itemType == SecKeyGetTypeID()) {
      key = (SecKeyRef)item;
      CFRetain(key);
    }
  }

  if (key == NULL) {
    secerr("SecItemImport: can't find key", err);
    goto cleanup;
  }

  if (cert == NULL) {
    secerr("SecItemImport: can't find cert", err);
    goto cleanup;
  }

  // Our keys gets set with "Imported Private Key"
  // as its label. Thanks Apple.
  list.count = 1;
  attributes[0].tag = kSecKeyPrintName;
  attributes[0].data =
    const_cast<void*>(reinterpret_cast<const void*>(label.data()));
  attributes[0].length = label.length() * sizeof(std::string::value_type);
  list.attr = attributes;

  err = SecKeychainItemModifyContent((SecKeychainItemRef)key, &list, 0, NULL);

  if (err != noErr) {
    secerr(
      "SecKeychainItemModifyContent: failed to update key print name",
      err);
    goto cleanup;
  }

  rv = true;

 cleanup:

  if (importKeychain != NULL) {
    CFRelease(importKeychain);
  }

  if (data != NULL) {
    CFRelease(data);
  }

  if (items != NULL) {
    CFRelease(items);
  }

  if (key != NULL) {
    CFRelease(key);
  }

  if (cert != NULL) {
    CFRelease(cert);
  }

  return rv;
}

bool DeleteKeypair(const std::string& publicKeySha1) {
  return false;
}

}  // namespace keytar
