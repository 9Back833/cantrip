#ifndef __STORAGE_MANAGER_BINDINGS_H__
#define __STORAGE_MANAGER_BINDINGS_H__

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#define KEY_VALUE_DATA_SIZE 100

typedef enum StorageManagerError {
  SmeSuccess = 0,
  SmeBundleIdInvalid,
  SmeBundleNotFound,
  SmeKeyNotFound,
  SmeValueInvalid,
  SmeKeyInvalid,
  SmeReadFailed,
  SmeWriteFailed,
  SmeDeleteFailed,
  SmeUnknownError,
} StorageManagerError;

typedef uint8_t KeyValueData[KEY_VALUE_DATA_SIZE];

#endif /* __STORAGE_MANAGER_BINDINGS_H__ */
