#NoEnv
#NoTrayIcon
#SingleInstance off
SetBatchLines, -1
ListLines, Off
Global A_Args:={}, MHGui:={}, Save:={}, Data:={}
SetModuleHandle()
class classCrypt {
class Encrypt {
String(AlgId, Mode := "", String := "", Key := "", IV := "", Encoding := "utf-8", Output := "BASE64") {
try
{
if !(ALGORITHM_IDENTIFIER := Crypt.Verify.EncryptionAlgorithm(AlgId))
throw Exception("Wrong ALGORITHM_IDENTIFIER", -1)
if !(ALG_HANDLE := Crypt.BCrypt.OpenAlgorithmProvider(ALGORITHM_IDENTIFIER))
throw Exception("BCryptOpenAlgorithmProvider failed", -1)
if (CHAINING_MODE := Crypt.Verify.ChainingMode(Mode))
if !(Crypt.BCrypt.SetProperty(ALG_HANDLE, Crypt.Constants.BCRYPT_CHAINING_MODE, CHAINING_MODE))
throw Exception("SetProperty failed", -1)
if !(KEY_HANDLE := Crypt.BCrypt.GenerateSymmetricKey(ALG_HANDLE, Key, Encoding))
throw Exception("GenerateSymmetricKey failed", -1)
if !(BLOCK_LENGTH := Crypt.BCrypt.GetProperty(ALG_HANDLE, Crypt.Constants.BCRYPT_BLOCK_LENGTH, 4))
throw Exception("GetProperty failed", -1)
cbInput := Crypt.Helper.StrPutVar(String, pbInput, Encoding)
if !(CIPHER_LENGTH := Crypt.BCrypt.Encrypt(KEY_HANDLE, pbInput, cbInput, IV, BLOCK_LENGTH, CIPHER_DATA, Crypt.Constants.BCRYPT_BLOCK_PADDING))
throw Exception("Encrypt failed", -1)
if !(ENCRYPT := Crypt.Helper.CryptBinaryToString(CIPHER_DATA, CIPHER_LENGTH, Output))
throw Exception("CryptBinaryToString failed", -1)
}
catch Exception
{
throw Exception
}
finally
{
if (KEY_HANDLE)
Crypt.BCrypt.DestroyKey(KEY_HANDLE)
if (ALG_HANDLE)
Crypt.BCrypt.CloseAlgorithmProvider(ALG_HANDLE)
}
return ENCRYPT
}
}
class Decrypt {
String(AlgId, Mode := "", String := "", Key := "", IV := "", Encoding := "utf-8", Input := "BASE64") {
try
{
if !(ALGORITHM_IDENTIFIER := Crypt.Verify.EncryptionAlgorithm(AlgId))
throw Exception("Wrong ALGORITHM_IDENTIFIER", -1)
if !(ALG_HANDLE := Crypt.BCrypt.OpenAlgorithmProvider(ALGORITHM_IDENTIFIER))
throw Exception("BCryptOpenAlgorithmProvider failed", -1)
if (CHAINING_MODE := Crypt.Verify.ChainingMode(Mode))
if !(Crypt.BCrypt.SetProperty(ALG_HANDLE, Crypt.Constants.BCRYPT_CHAINING_MODE, CHAINING_MODE))
throw Exception("SetProperty failed", -1)
if !(KEY_HANDLE := Crypt.BCrypt.GenerateSymmetricKey(ALG_HANDLE, Key, Encoding))
throw Exception("GenerateSymmetricKey failed", -1)
if !(CIPHER_LENGTH := Crypt.Helper.CryptStringToBinary(String, CIPHER_DATA, Input))
throw Exception("CryptStringToBinary failed", -1)
if !(BLOCK_LENGTH := Crypt.BCrypt.GetProperty(ALG_HANDLE, Crypt.Constants.BCRYPT_BLOCK_LENGTH, 4))
throw Exception("GetProperty failed", -1)
if !(DECRYPT_LENGTH := Crypt.BCrypt.Decrypt(KEY_HANDLE, CIPHER_DATA, CIPHER_LENGTH, IV, BLOCK_LENGTH, DECRYPT_DATA, Crypt.Constants.BCRYPT_BLOCK_PADDING))
throw Exception("Decrypt failed", -1)
DECRYPT := StrGet(&DECRYPT_DATA, DECRYPT_LENGTH, Encoding)
}
catch Exception
{
throw Exception
}
finally
{
if (KEY_HANDLE)
Crypt.BCrypt.DestroyKey(KEY_HANDLE)
if (ALG_HANDLE)
Crypt.BCrypt.CloseAlgorithmProvider(ALG_HANDLE)
}
return DECRYPT
}
}
class Hash {
String(AlgId, String, Encoding := "utf-8", Output := "HEXRAW") {
try
{
if !(ALGORITHM_IDENTIFIER := Crypt.Verify.HashAlgorithm(AlgId))
throw Exception("Wrong ALGORITHM_IDENTIFIER", -1)
if !(ALG_HANDLE := Crypt.BCrypt.OpenAlgorithmProvider(ALGORITHM_IDENTIFIER))
throw Exception("BCryptOpenAlgorithmProvider failed", -1)
if !(HASH_HANDLE := Crypt.BCrypt.CreateHash(ALG_HANDLE))
throw Exception("CreateHash failed", -1)
cbInput := Crypt.Helper.StrPutVar(String, pbInput, Encoding)
if !(Crypt.BCrypt.HashData(HASH_HANDLE, pbInput, cbInput))
throw Exception("HashData failed", -1)
if !(HASH_LENGTH := Crypt.BCrypt.GetProperty(ALG_HANDLE, Crypt.Constants.BCRYPT_HASH_LENGTH, 4))
throw Exception("GetProperty failed", -1)
if !(Crypt.BCrypt.FinishHash(HASH_HANDLE, HASH_DATA, HASH_LENGTH))
throw Exception("FinishHash failed", -1)
if !(HASH := Crypt.Helper.CryptBinaryToString(HASH_DATA, HASH_LENGTH, Output))
throw Exception("CryptBinaryToString failed", -1)
}
catch Exception
{
throw Exception
}
finally
{
if (HASH_HANDLE)
Crypt.BCrypt.DestroyHash(HASH_HANDLE)
if (ALG_HANDLE)
Crypt.BCrypt.CloseAlgorithmProvider(ALG_HANDLE)
}
return HASH
}
File(AlgId, FileName, Bytes := 1048576, Offset := 0, Length := -1, Encoding := "utf-8", Output := "HEXRAW"){
try
{
if !(ALGORITHM_IDENTIFIER := Crypt.Verify.HashAlgorithm(AlgId))
throw Exception("Wrong ALGORITHM_IDENTIFIER", -1)
if !(ALG_HANDLE := Crypt.BCrypt.OpenAlgorithmProvider(ALGORITHM_IDENTIFIER))
throw Exception("BCryptOpenAlgorithmProvider failed", -1)
if !(HASH_HANDLE := Crypt.BCrypt.CreateHash(ALG_HANDLE))
throw Exception("CreateHash failed", -1)
if !(IsObject(File := FileOpen(FileName, "r", Encoding)))
throw Exception("Failed to open file: " FileName, -1)
Length := Length < 0 ? File.Length - Offset : Length
if ((Offset + Length) > File.Length)
throw Exception("Invalid parameters offset / length!", -1)
while (Length > Bytes) && (Dataread := File.RawRead(Data, Bytes))
{
if !(Crypt.BCrypt.HashData(HASH_HANDLE, Data, Dataread))
throw Exception("HashData failed", -1)
Length -= Dataread
}
if (Length > 0)
{
if (Dataread := File.RawRead(Data, Length))
{
if !(Crypt.BCrypt.HashData(HASH_HANDLE, Data, Dataread))
throw Exception("HashData failed", -1)
}
}
if !(HASH_LENGTH := Crypt.BCrypt.GetProperty(ALG_HANDLE, Crypt.Constants.BCRYPT_HASH_LENGTH, 4))
throw Exception("GetProperty failed", -1)
if !(Crypt.BCrypt.FinishHash(HASH_HANDLE, HASH_DATA, HASH_LENGTH))
throw Exception("FinishHash failed", -1)
if !(HASH := Crypt.Helper.CryptBinaryToString(HASH_DATA, HASH_LENGTH, Output))
throw Exception("CryptBinaryToString failed", -1)
}
catch Exception
{
throw Exception
}
finally
{
if (File)
File.Close()
if (HASH_HANDLE)
Crypt.BCrypt.DestroyHash(HASH_HANDLE)
if (ALG_HANDLE)
Crypt.BCrypt.CloseAlgorithmProvider(ALG_HANDLE)
}
return HASH
}
HMAC(AlgId, String, Hmac, Encoding := "utf-8", Output := "HEXRAW") {
try
{
if !(ALGORITHM_IDENTIFIER := Crypt.Verify.HashAlgorithm(AlgId))
throw Exception("Wrong ALGORITHM_IDENTIFIER", -1)
if !(ALG_HANDLE := Crypt.BCrypt.OpenAlgorithmProvider(ALGORITHM_IDENTIFIER, Crypt.Constants.BCRYPT_ALG_HANDLE_HMAC_FLAG))
throw Exception("BCryptOpenAlgorithmProvider failed", -1)
if !(HASH_HANDLE := Crypt.BCrypt.CreateHash(ALG_HANDLE, Hmac, Encoding))
throw Exception("CreateHash failed", -1)
cbInput := Crypt.helper.StrPutVar(String, pbInput, Encoding)
if !(Crypt.BCrypt.HashData(HASH_HANDLE, pbInput, cbInput))
throw Exception("HashData failed", -1)
if !(HASH_LENGTH := Crypt.BCrypt.GetProperty(ALG_HANDLE, Crypt.Constants.BCRYPT_HASH_LENGTH, 4))
throw Exception("GetProperty failed", -1)
if !(Crypt.BCrypt.FinishHash(HASH_HANDLE, HASH_DATA, HASH_LENGTH))
throw Exception("FinishHash failed", -1)
if !(HMAC := Crypt.Helper.CryptBinaryToString(HASH_DATA, HASH_LENGTH, Output))
throw Exception("CryptBinaryToString failed", -1)
}
catch Exception
{
throw Exception
}
finally
{
if (HASH_HANDLE)
Crypt.BCrypt.DestroyHash(HASH_HANDLE)
if (ALG_HANDLE)
Crypt.BCrypt.CloseAlgorithmProvider(ALG_HANDLE)
}
return HMAC
}
PBKDF2(AlgId, Password, Salt, Iterations := 4096, KeySize := 256, Encoding := "utf-8", Output := "HEXRAW") {
try
{
if !(ALGORITHM_IDENTIFIER := Crypt.Verify.HashAlgorithm(AlgId))
throw Exception("Wrong ALGORITHM_IDENTIFIER", -1)
if !(ALG_HANDLE := Crypt.BCrypt.OpenAlgorithmProvider(ALGORITHM_IDENTIFIER, Crypt.Constants.BCRYPT_ALG_HANDLE_HMAC_FLAG))
throw Exception("BCryptOpenAlgorithmProvider failed", -1)
if !(Crypt.BCrypt.DeriveKeyPBKDF2(ALG_HANDLE, Password, Salt, Iterations, PBKDF2_DATA, KeySize / 8, Encoding))
throw Exception("CreateHash failed", -1)
if !(PBKDF2 := Crypt.Helper.CryptBinaryToString(PBKDF2_DATA , KeySize / 8, Output))
throw Exception("CryptBinaryToString failed", -1)
}
catch Exception
{
throw Exception
}
finally
{
if (ALG_HANDLE)
Crypt.BCrypt.CloseAlgorithmProvider(ALG_HANDLE)
}
return PBKDF2
}
}
class BCrypt {
static hBCRYPT := DllCall("LoadLibrary", "str", "bcrypt.dll", "ptr")
static STATUS_SUCCESS := 0
CloseAlgorithmProvider(hAlgorithm) {
DllCall("bcrypt\BCryptCloseAlgorithmProvider", "ptr", hAlgorithm, "uint", 0)
}
CreateHash(hAlgorithm, hmac := 0, encoding := "utf-8") {
if (hmac)
cbSecret := Crypt.helper.StrPutVar(hmac, pbSecret, encoding)
NT_STATUS := DllCall("bcrypt\BCryptCreateHash", "ptr",  hAlgorithm
, "ptr*", phHash
, "ptr",  pbHashObject := 0
, "uint", cbHashObject := 0
, "ptr",  (pbSecret ? &pbSecret : 0)
, "uint", (cbSecret ? cbSecret : 0)
, "uint", dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
return phHash
return false
}
DeriveKeyPBKDF2(hPrf, Password, Salt, cIterations, ByRef pbDerivedKey, cbDerivedKey, Encoding := "utf-8") {
cbPassword := Crypt.Helper.StrPutVar(Password, pbPassword, Encoding)
cbSalt := Crypt.Helper.StrPutVar(Salt, pbSalt, Encoding)
VarSetCapacity(pbDerivedKey, cbDerivedKey, 0)
NT_STATUS := DllCall("bcrypt\BCryptDeriveKeyPBKDF2", "ptr",   hPrf
, "ptr",   &pbPassword
, "uint",  cbPassword
, "ptr",   &pbSalt
, "uint",  cbSalt
, "int64", cIterations
, "ptr",   &pbDerivedKey
, "uint",  cbDerivedKey
, "uint",  dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
return true
return false
}
DestroyHash(hHash) {
DllCall("bcrypt\BCryptDestroyHash", "ptr", hHash)
}
DestroyKey(hKey) {
DllCall("bcrypt\BCryptDestroyKey", "ptr", hKey)
}
Decrypt(hKey, ByRef String, cbInput, IV, BCRYPT_BLOCK_LENGTH, ByRef pbOutput, dwFlags) {
VarSetCapacity(pbInput, cbInput, 0)
DllCall("msvcrt\memcpy", "ptr", &pbInput, "ptr", &String, "ptr", cbInput)
if (IV != "")
{
cbIV := VarSetCapacity(pbIV, BCRYPT_BLOCK_LENGTH, 0)
StrPut(IV, &pbIV, BCRYPT_BLOCK_LENGTH, Encoding)
}
NT_STATUS := DllCall("bcrypt\BCryptDecrypt", "ptr",   hKey
, "ptr",   &pbInput
, "uint",  cbInput
, "ptr",   0
, "ptr",   (pbIV ? &pbIV : 0)
, "uint",  (cbIV ? &cbIV : 0)
, "ptr",   0
, "uint",  0
, "uint*", cbOutput
, "uint",  dwFlags)
if (NT_STATUS = this.STATUS_SUCCESS)
{
VarSetCapacity(pbOutput, cbOutput, 0)
NT_STATUS := DllCall("bcrypt\BCryptDecrypt", "ptr",   hKey
, "ptr",   &pbInput
, "uint",  cbInput
, "ptr",   0
, "ptr",   (pbIV ? &pbIV : 0)
, "uint",  (cbIV ? &cbIV : 0)
, "ptr",   &pbOutput
, "uint",  cbOutput
, "uint*", cbOutput
, "uint",  dwFlags)
if (NT_STATUS = this.STATUS_SUCCESS)
{
return cbOutput
}
}
return false
}
Encrypt(hKey, ByRef pbInput, cbInput, IV, BCRYPT_BLOCK_LENGTH, ByRef pbOutput, dwFlags := 0) {
if (IV != "")
{
cbIV := VarSetCapacity(pbIV, BCRYPT_BLOCK_LENGTH, 0)
StrPut(IV, &pbIV, BCRYPT_BLOCK_LENGTH, Encoding)
}
NT_STATUS := DllCall("bcrypt\BCryptEncrypt", "ptr",   hKey
, "ptr",   &pbInput
, "uint",  cbInput
, "ptr",   0
, "ptr",   (pbIV ? &pbIV : 0)
, "uint",  (cbIV ? &cbIV : 0)
, "ptr",   0
, "uint",  0
, "uint*", cbOutput
, "uint",  dwFlags)
if (NT_STATUS = this.STATUS_SUCCESS)
{
VarSetCapacity(pbOutput, cbOutput, 0)
NT_STATUS := DllCall("bcrypt\BCryptEncrypt", "ptr",   hKey
, "ptr",   &pbInput
, "uint",  cbInput
, "ptr",   0
, "ptr",   (pbIV ? &pbIV : 0)
, "uint",  (cbIV ? &cbIV : 0)
, "ptr",   &pbOutput
, "uint",  cbOutput
, "uint*", cbOutput
, "uint",  dwFlags)
if (NT_STATUS = this.STATUS_SUCCESS)
{
return cbOutput
}
}
return false
}
EnumAlgorithms(dwAlgOperations) {
NT_STATUS := DllCall("bcrypt\BCryptEnumAlgorithms", "uint",  dwAlgOperations
, "uint*", pAlgCount
, "ptr*",  ppAlgList
, "uint",  dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
{
addr := ppAlgList, BCRYPT_ALGORITHM_IDENTIFIER := []
loop % pAlgCount
{
BCRYPT_ALGORITHM_IDENTIFIER[A_Index, "Name"]  := StrGet(NumGet(addr + A_PtrSize * 0, "uptr"), "utf-16")
BCRYPT_ALGORITHM_IDENTIFIER[A_Index, "Class"] := NumGet(addr + A_PtrSize * 1, "uint")
BCRYPT_ALGORITHM_IDENTIFIER[A_Index, "Flags"] := NumGet(addr + A_PtrSize * 1 + 4, "uint")
addr += A_PtrSize * 2
}
return BCRYPT_ALGORITHM_IDENTIFIER
}
return false
}
EnumProviders(pszAlgId) {
NT_STATUS := DllCall("bcrypt\BCryptEnumProviders", "ptr",   pszAlgId
, "uint*", pImplCount
, "ptr*",  ppImplList
, "uint",  dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
{
addr := ppImplList, BCRYPT_PROVIDER_NAME := []
loop % pImplCount
{
BCRYPT_PROVIDER_NAME.Push(StrGet(NumGet(addr + A_PtrSize * 0, "uptr"), "utf-16"))
addr += A_PtrSize
}
return BCRYPT_PROVIDER_NAME
}
return false
}
FinishHash(hHash, ByRef pbOutput, cbOutput) {
VarSetCapacity(pbOutput, cbOutput, 0)
NT_STATUS := DllCall("bcrypt\BCryptFinishHash", "ptr",  hHash
, "ptr",  &pbOutput
, "uint", cbOutput
, "uint", dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
return cbOutput
return false
}
GenerateSymmetricKey(hAlgorithm, Key, Encoding := "utf-8") {
cbSecret := Crypt.Helper.StrPutVar(Key, pbSecret, Encoding)
NT_STATUS := DllCall("bcrypt\BCryptGenerateSymmetricKey", "ptr",  hAlgorithm
, "ptr*", phKey
, "ptr",  0
, "uint", 0
, "ptr",  &pbSecret
, "uint", cbSecret
, "uint", dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
return phKey
return false
}
GetProperty(hObject, pszProperty, cbOutput) {
NT_STATUS := DllCall("bcrypt\BCryptGetProperty", "ptr",   hObject
, "ptr",   &pszProperty
, "uint*", pbOutput
, "uint",  cbOutput
, "uint*", pcbResult
, "uint",  dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
return pbOutput
return false
}
HashData(hHash, ByRef pbInput, cbInput) {
NT_STATUS := DllCall("bcrypt\BCryptHashData", "ptr",  hHash
, "ptr",  &pbInput
, "uint", cbInput
, "uint", dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
return true
return false
}
OpenAlgorithmProvider(pszAlgId, dwFlags := 0, pszImplementation := 0) {
NT_STATUS := DllCall("bcrypt\BCryptOpenAlgorithmProvider", "ptr*", phAlgorithm
, "ptr",  &pszAlgId
, "ptr",  pszImplementation
, "uint", dwFlags)
if (NT_STATUS = this.STATUS_SUCCESS)
return phAlgorithm
return false
}
SetProperty(hObject, pszProperty, pbInput) {
bInput := StrLen(pbInput)
NT_STATUS := DllCall("bcrypt\BCryptSetProperty", "ptr",   hObject
, "ptr",   &pszProperty
, "ptr",   &pbInput
, "uint",  bInput
, "uint",  dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
return true
return false
}
}
class Helper {
static hCRYPT32 := DllCall("LoadLibrary", "str", "crypt32.dll", "ptr")
CryptBinaryToString(ByRef pbBinary, cbBinary, dwFlags := "BASE64") {
static CRYPT_STRING := { "BASE64": 0x1, "BINARY": 0x2, "HEX": 0x4, "HEXRAW": 0xc }
static CRYPT_STRING_NOCRLF := 0x40000000
if (DllCall("crypt32\CryptBinaryToString", "ptr",   &pbBinary
, "uint",  cbBinary
, "uint",  (CRYPT_STRING[dwFlags] | CRYPT_STRING_NOCRLF)
, "ptr",   0
, "uint*", pcchString))
{
VarSetCapacity(pszString, pcchString << !!A_IsUnicode, 0)
if (DllCall("crypt32\CryptBinaryToString", "ptr",   &pbBinary
, "uint",  cbBinary
, "uint",  (CRYPT_STRING[dwFlags] | CRYPT_STRING_NOCRLF)
, "ptr",   &pszString
, "uint*", pcchString))
{
return StrGet(&pszString)
}
}
return false
}
CryptStringToBinary(pszString, ByRef pbBinary, dwFlags := "BASE64") {
static CRYPT_STRING := { "BASE64": 0x1, "BINARY": 0x2, "HEX": 0x4, "HEXRAW": 0xc }
if (DllCall("crypt32\CryptStringToBinary", "ptr",   &pszString
, "uint",  0
, "uint",  CRYPT_STRING[dwFlags]
, "ptr",   0
, "uint*", pcbBinary
, "ptr",   0
, "ptr",   0))
{
VarSetCapacity(pbBinary, pcbBinary, 0)
if (DllCall("crypt32\CryptStringToBinary", "ptr",   &pszString
, "uint",  0
, "uint",  CRYPT_STRING[dwFlags]
, "ptr",   &pbBinary
, "uint*", pcbBinary
, "ptr",   0
, "ptr",   0))
{
return pcbBinary
}
}
return false
}
StrPutVar(String, ByRef Data, Encoding) {
if (Encoding = "hex")
{
String := InStr(String, "0x") ? SubStr(String, 3) : String
VarSetCapacity(Data, (Length := StrLen(String) // 2), 0)
loop % Length
NumPut("0x" SubStr(String, 2 * A_Index - 1, 2), Data, A_Index - 1, "char")
return Length
}
else
{
VarSetCapacity(Data, Length := StrPut(String, Encoding) * ((Encoding = "utf-16" || Encoding = "cp1200") ? 2 : 1) - 1)
return StrPut(String, &Data, Length, Encoding)
}
}
}
class Verify {
ChainingMode(ChainMode) {
switch ChainMode
{
case "CBC", "ChainingModeCBC": return Crypt.Constants.BCRYPT_CHAIN_MODE_CBC
case "CFB", "ChainingModeCFB": return Crypt.Constants.BCRYPT_CHAIN_MODE_CFB
case "ECB", "ChainingModeECB": return Crypt.Constants.BCRYPT_CHAIN_MODE_ECB
default: return ""
}
}
EncryptionAlgorithm(Algorithm) {
switch Algorithm
{
case "AES":                return Crypt.Constants.BCRYPT_AES_ALGORITHM
case "DES":                return Crypt.Constants.BCRYPT_DES_ALGORITHM
case "RC2":                return Crypt.Constants.BCRYPT_RC2_ALGORITHM
case "RC4":                return Crypt.Constants.BCRYPT_RC4_ALGORITHM
default: return ""
}
}
HashAlgorithm(Algorithm) {
switch Algorithm
{
case "MD2":               return Crypt.Constants.BCRYPT_MD2_ALGORITHM
case "MD4":               return Crypt.Constants.BCRYPT_MD4_ALGORITHM
case "MD5":               return Crypt.Constants.BCRYPT_MD5_ALGORITHM
case "SHA1", "SHA-1":     return Crypt.Constants.BCRYPT_SHA1_ALGORITHM
case "SHA256", "SHA-256": return Crypt.Constants.BCRYPT_SHA256_ALGORITHM
case "SHA384", "SHA-384": return Crypt.Constants.BCRYPT_SHA384_ALGORITHM
case "SHA512", "SHA-512": return Crypt.Constants.BCRYPT_SHA512_ALGORITHM
default: return ""
}
}
}
class Constants {
static BCRYPT_ALG_HANDLE_HMAC_FLAG            := 0x00000008
static BCRYPT_BLOCK_PADDING                   := 0x00000001
static BCRYPT_CIPHER_OPERATION                := 0x00000001
static BCRYPT_HASH_OPERATION                  := 0x00000002
static BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION := 0x00000004
static BCRYPT_SECRET_AGREEMENT_OPERATION      := 0x00000008
static BCRYPT_SIGNATURE_OPERATION             := 0x00000010
static BCRYPT_RNG_OPERATION                   := 0x00000020
static BCRYPT_KEY_DERIVATION_OPERATION        := 0x00000040
static BCRYPT_3DES_ALGORITHM                  := "3DES"
static BCRYPT_3DES_112_ALGORITHM              := "3DES_112"
static BCRYPT_AES_ALGORITHM                   := "AES"
static BCRYPT_AES_CMAC_ALGORITHM              := "AES-CMAC"
static BCRYPT_AES_GMAC_ALGORITHM              := "AES-GMAC"
static BCRYPT_DES_ALGORITHM                   := "DES"
static BCRYPT_DESX_ALGORITHM                  := "DESX"
static BCRYPT_MD2_ALGORITHM                   := "MD2"
static BCRYPT_MD4_ALGORITHM                   := "MD4"
static BCRYPT_MD5_ALGORITHM                   := "MD5"
static BCRYPT_RC2_ALGORITHM                   := "RC2"
static BCRYPT_RC4_ALGORITHM                   := "RC4"
static BCRYPT_RNG_ALGORITHM                   := "RNG"
static BCRYPT_SHA1_ALGORITHM                  := "SHA1"
static BCRYPT_SHA256_ALGORITHM                := "SHA256"
static BCRYPT_SHA384_ALGORITHM                := "SHA384"
static BCRYPT_SHA512_ALGORITHM                := "SHA512"
static BCRYPT_PBKDF2_ALGORITHM                := "PBKDF2"
static BCRYPT_XTS_AES_ALGORITHM               := "XTS-AES"
static BCRYPT_BLOCK_LENGTH                    := "BlockLength"
static BCRYPT_CHAINING_MODE                   := "ChainingMode"
static BCRYPT_CHAIN_MODE_CBC                  := "ChainingModeCBC"
static BCRYPT_CHAIN_MODE_CCM                  := "ChainingModeCCM"
static BCRYPT_CHAIN_MODE_CFB                  := "ChainingModeCFB"
static BCRYPT_CHAIN_MODE_ECB                  := "ChainingModeECB"
static BCRYPT_CHAIN_MODE_GCM                  := "ChainingModeGCM"
static BCRYPT_HASH_LENGTH                     := "HashDigestLength"
static BCRYPT_OBJECT_LENGTH                   := "ObjectLength"
}
}
LoadGDIplus(){
UPtr()
VarSetCapacity(startInput, A_PtrSize = 8 ? 24 : 16, 0), startInput := Chr(1)
HModuleGdip := DllCall("LoadLibrary", "Str", "gdiplus", "Ptr")
DllCall("gdiplus\GdiplusStartup", "Ptr*", pToken, "Ptr", &startInput, "Ptr", 0)
A_Args.Proc:={}
A_Args.Proc.BitBlt                  := DllCall("GetProcAddress", "Ptr", DllCall("GetModuleHandle", "Str", "gdi32", "Ptr"), "AStr", "BitBlt", "Ptr")
A_Args.Proc.CloneBitmap             := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipCloneBitmapArea", "Ptr")
A_Args.Proc.BitmapLock              := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipBitmapLockBits", "Ptr")
A_Args.Proc.BitmapUnlock            := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipBitmapUnlockBits", "Ptr")
A_Args.Proc.DisposeImage            := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipDisposeImage", "Ptr")
A_Args.Proc.DrawImageRect           := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipDrawImageRect", "Ptr")
A_Args.Proc.DrawImageFast           := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipDrawImage", "Ptr")
A_Args.Proc.GetImageGraphic         := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipGetImageGraphicsContext", "Ptr")
A_Args.Proc.CreateBitmapFromScan    := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipCreateBitmapFromScan0", "Ptr")
A_Args.Proc.CreateBitmapFromHBITMAP := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipCreateBitmapFromHBITMAP", "Ptr")
A_Args.Proc.CreateBitmapFromFile    := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipCreateBitmapFromFile", "Ptr")
}
Gdip_GetFile(url, filename){
static a:="AutoHotkey/" A_AhkVersion, c:=0, s:=0
if (!(o := FileOpen(filename, "w")) || !DllCall("LoadLibrary", "str", "wininet") || !(h := DllCall("wininet\InternetOpen", "str", a, "uint", 1, "ptr", 0, "ptr", 0, "uint", 0, "ptr")))
return 0
if (f := DllCall("wininet\InternetOpenUrl", "ptr", h, "str", url, "ptr", 0, "uint", 0, "uint", 0x80003000, "ptr", 0, "ptr")){
while (DllCall("wininet\InternetQueryDataAvailable", "ptr", f, "uint*", s, "uint", 0, "ptr", 0) && s>0){
VarSetCapacity(b, s, 0)
DllCall("wininet\InternetReadFile", "ptr", f, "ptr", &b, "uint", s, "uint*", r), c += r
o.rawWrite(b, r)
}
DllCall("wininet\InternetCloseHandle", "ptr", f)
}
DllCall("wininet\InternetCloseHandle", "ptr", h)
o.close()
return c
}
GetInBetween(string,PontA,PontB,ByRef Pos:=""){
Pos := RegExMatch(string, "(?<=" PontA ")(.*)(?=" PontB ")", Info)
Return Info
}
Gdip_UTF(In){
Return StrGet(&In,"UTF-8")
}
Gdip_GetImageDimensions(pBitmap, ByRef Width, ByRef Height){
If StrLen(pBitmap)<3
Return -1
Width := 0, Height := 0
E := DllCall("gdiplus\GdipGetImageDimension", "UPtr", pBitmap, "float*", Width, "float*", Height)
Width := Round(Width)
Height := Round(Height)
return E
}
Gdip_RunMCode(mcode){
static e := {1:4, 2:1}, c := (A_PtrSize=8) ? "x64" : "x86"
if (!regexmatch(mcode, "^([0-9]+),(" c ":|.*?," c ":)([^,]+)", m))
return
if (!DllCall("crypt32\CryptStringToBinary", "str", m3, "uint", StrLen(m3), "uint", e[m1], "ptr", 0, "uintp", s, "ptr", 0, "ptr", 0))
return
p := DllCall("GlobalAlloc", "uint", 0, "ptr", s, "ptr")
DllCall("VirtualProtect", "ptr", p, "ptr", s, "uint", 0x40, "uint*", op)
if (DllCall("crypt32\CryptStringToBinary", "str", m3, "uint", StrLen(m3), "uint", e[m1], "ptr", p, "uint*", s, "ptr", 0, "ptr", 0))
return p
DllCall("GlobalFree", "ptr", p)
}
MsgData(Obj, Type:=""){
if (!IsObject(obj)){
try
Obj := Data["Msg"][Obj]
MsgBox, % Type, % Obj["T"][Save.Ling], % Obj["M"][Save.Ling]
Return
}
MsgBox, % Type, % Obj.1, % Obj.2
}
Gdip_CreateBitmap(Width, Height, PixelFormat:=0, Stride:=0, Scan0:=0){
pBitmap := 0
If !PixelFormat
PixelFormat := 0x26200A
DllCall(A_Args.Proc.CreateBitmapFromScan, "int", Width, "int", Height, "int", Stride, "int", PixelFormat, "UPtr", Scan0, "UPtr*", pBitmap)
Return pBitmap
}
Gdip_CreateBitmapFromFile(sFile, IconNumber:=1, IconSize:="", useICM:=0){
pBitmap := 0
, pBitmapOld := 0
, hIcon := 0
SplitPath sFile,,, Extension
if RegExMatch(Extension, "^(?i:exe|dll)$"){
Sizes := IconSize ? IconSize : 256 "|" 128 "|" 64 "|" 48 "|" 32 "|" 16
BufSize := 16 + (2*A_PtrSize)
VarSetCapacity(buf, BufSize, 0)
For eachSize, Size in StrSplit( Sizes, "|" ){
DllCall("PrivateExtractIcons", "str", sFile, "int", IconNumber-1, "int", Size, "int", Size, "UPtr*", hIcon, "UPtr*", 0, "uint", 1, "uint", 0)
if !hIcon
continue
if !DllCall("GetIconInfo", "UPtr", hIcon, "UPtr", &buf){
DllCall("DestroyIcon", "UPtr", hIcon)
continue
}
hbmMask := NumGet(buf, 12 + (A_PtrSize - 4))
hbmColor := NumGet(buf, 12 + (A_PtrSize - 4) + A_PtrSize)
if !(hbmColor && DllCall("GetObject", "UPtr", hbmColor, "int", BufSize, "UPtr", &buf)){
DllCall("DestroyIcon", "UPtr", hIcon)
continue
}
break
}
if !hIcon
return -1
Width := NumGet(buf, 4, "int"), Height := NumGet(buf, 8, "int")
hbm := CreateDIBSection(Width, -Height), hdc := CreateCompatibleDC(), obm := SelectObject(hdc, hbm)
if !DllCall("DrawIconEx", "UPtr", hdc, "int", 0, "int", 0, "UPtr", hIcon, "uint", Width, "uint", Height, "uint", 0, "UPtr", 0, "uint", 3){
DllCall("DestroyIcon", "UPtr", hIcon)
return -2
}
VarSetCapacity(dib, 104)
, DllCall("GetObject", "UPtr", hbm, "int", A_PtrSize = 8 ? 104 : 84, "UPtr", &dib)
, Stride := NumGet(dib, 12, "Int"), Scan0 := NumGet(dib, 20 + (A_PtrSize = 8 ? 4 : 0))
, DllCall(A_Args.Proc.CreateBitmapFromScan, "int", Width, "int", Height, "int", Stride, "int", 0x26200A, "UPtr", Scan0, "UPtr*", pBitmapOld)
, DllCall(A_Args.Proc.CreateBitmapFromScan, "int", Width, "int", Height, "int", 0, "int", 0x26200A, "UPtr", 0, "UPtr*", pBitmap)
, DllCall(A_Args.Proc.GetImageGraphic, "UPtr", pBitmap, "UPtr*", _G)
SelectObject(hdc, obm)
, DeleteObject(hbm)
, DeleteDC(hdc)
, Gdip_DeleteGraphics(_G)
, Gdip_DisposeImage(pBitmapOld)
, DllCall("DestroyIcon", "UPtr", hIcon)
} else {
function2call := (useICM=1) ? "GdipCreateBitmapFromFileICM" : "GdipCreateBitmapFromFile"
, E := DllCall("gdiplus\" function2call, "WStr", sFile, "UPtr*", pBitmap)
}
return pBitmap
}
CreateRectF(ByRef RectF, x, y, w, h){
VarSetCapacity(RectF, 16)
NumPut(x, RectF, 0, "float"), NumPut(y, RectF, 4, "float")
NumPut(w, RectF, 8, "float"), NumPut(h, RectF, 12, "float")
}
CryptBinaryToString(ByRef pbBinary, cbBinary, dwFlags := "BASE64") {
static CRYPT_STRING := { "BASE64": 0x1, "BINARY": 0x2, "HEX": 0x4, "HEXRAW": 0xc }
static CRYPT_STRING_NOCRLF := 0x40000000
if (DllCall("crypt32\CryptBinaryToString", "ptr", &pbBinary, "uint", cbBinary, "uint", (CRYPT_STRING[dwFlags] | CRYPT_STRING_NOCRLF), "ptr", 0, "uint*", pcchString))
{
VarSetCapacity(pszString, pcchString << !!A_IsUnicode, 0)
if (DllCall("crypt32\CryptBinaryToString", "ptr", &pbBinary, "uint", cbBinary, "uint", (CRYPT_STRING[dwFlags] | CRYPT_STRING_NOCRLF), "ptr", &pszString, "uint*", pcchString))
{
return StrGet(&pszString)
}
}
return false
}
CryptStringToBinary(pszString, ByRef pbBinary) {
if (DllCall("crypt32\CryptStringToBinary", "ptr", &pszString, "uint", 0, "uint", 0x1, "ptr", 0, "uint*", pcbBinary, "ptr", 0, "ptr", 0))
{
VarSetCapacity(pbBinary, pcbBinary, 0)
if (DllCall("crypt32\CryptStringToBinary", "ptr", &pszString, "uint", 0, "uint", 0x1, "ptr", &pbBinary, "uint*", pcbBinary, "ptr", 0, "ptr", 0))
{
return pcbBinary
}
}
return false
}
Gdip_SaveBitmapToFile(pBitmap, sOutput, Quality:=75, toBase64:=0){
Static Ptr := "UPtr"
nCount := 0
nSize := 0
_p := 0
SplitPath sOutput,,, Extension
If !RegExMatch(Extension, "^(?i:BMP|DIB|RLE|JPG|JPEG|JPE|JFIF|GIF|TIF|TIFF|PNG)$")
Return -1
Extension := "." Extension
DllCall("gdiplus\GdipGetImageEncodersSize", "uint*", nCount, "uint*", nSize)
VarSetCapacity(ci, nSize)
DllCall("gdiplus\GdipGetImageEncoders", "uint", nCount, "uint", nSize, Ptr, &ci)
If !(nCount && nSize)
Return -2
If (A_IsUnicode)
{
StrGet_Name := "StrGet"
N := (A_AhkVersion < 2) ? nCount : "nCount"
Loop %N%
{
sString := %StrGet_Name%(NumGet(ci, (idx := (48+7*A_PtrSize)*(A_Index-1))+32+3*A_PtrSize), "UTF-16")
If !InStr(sString, "*" Extension)
Continue
pCodec := &ci+idx
Break
}
} Else
{
N := (A_AhkVersion < 2) ? nCount : "nCount"
Loop %N%
{
Location := NumGet(ci, 76*(A_Index-1)+44)
nSize := DllCall("WideCharToMultiByte", "uint", 0, "uint", 0, "uint", Location, "int", -1, "uint", 0, "int", 0, "uint", 0, "uint", 0)
VarSetCapacity(sString, nSize)
DllCall("WideCharToMultiByte", "uint", 0, "uint", 0, "uint", Location, "int", -1, "str", sString, "int", nSize, "uint", 0, "uint", 0)
If !InStr(sString, "*" Extension)
Continue
pCodec := &ci+76*(A_Index-1)
Break
}
}
If !pCodec
Return -3
If (Quality!=75)
{
Quality := (Quality < 0) ? 0 : (Quality > 100) ? 100 : Quality
If (quality>90 && toBase64=1)
Quality := 90
If RegExMatch(Extension, "^\.(?i:JPG|JPEG|JPE|JFIF)$")
{
DllCall("gdiplus\GdipGetEncoderParameterListSize", Ptr, pBitmap, Ptr, pCodec, "uint*", nSize)
VarSetCapacity(EncoderParameters, nSize, 0)
DllCall("gdiplus\GdipGetEncoderParameterList", Ptr, pBitmap, Ptr, pCodec, "uint", nSize, Ptr, &EncoderParameters)
nCount := NumGet(EncoderParameters, "UInt")
N := (A_AhkVersion < 2) ? nCount : "nCount"
Loop %N%
{
elem := (24+A_PtrSize)*(A_Index-1) + 4 + (pad := A_PtrSize = 8 ? 4 : 0)
If (NumGet(EncoderParameters, elem+16, "UInt") = 1) && (NumGet(EncoderParameters, elem+20, "UInt") = 6)
{
_p := elem+&EncoderParameters-pad-4
NumPut(Quality, NumGet(NumPut(4, NumPut(1, _p+0)+20, "UInt")), "UInt")
Break
}
}
}
}
If (toBase64=1)
{
DllCall("ole32\CreateStreamOnHGlobal", "ptr",0, "int",true, "ptr*",pStream)
_E := DllCall("gdiplus\GdipSaveImageToStream", "ptr",pBitmap, "ptr",pStream, "ptr",pCodec, "uint", _p ? _p : 0)
If _E
Return -6
DllCall("ole32\GetHGlobalFromStream", "ptr",pStream, "uint*",hData)
pData := DllCall("GlobalLock", "ptr",hData, "ptr")
nSize := DllCall("GlobalSize", "uint",pData)
VarSetCapacity(bin, nSize, 0)
DllCall("RtlMoveMemory", "ptr",&bin, "ptr",pData, "uptr",nSize)
DllCall("GlobalUnlock", "ptr",hData)
ObjRelease(pStream)
DllCall("GlobalFree", "ptr",hData)
DllCall("Crypt32.dll\CryptBinaryToStringA", "ptr",&bin, "uint",nSize, "uint",0x40000001, "ptr",0, "uint*",base64Length)
VarSetCapacity(base64, base64Length, 0)
_E := DllCall("Crypt32.dll\CryptBinaryToStringA", "ptr",&bin, "uint",nSize, "uint",0x40000001, "ptr",&base64, "uint*",base64Length)
If !_E
Return -7
VarSetCapacity(bin, 0)
Return StrGet(&base64, base64Length, "CP0")
}
_E := DllCall("gdiplus\GdipSaveImageToFile", Ptr, pBitmap, "WStr", sOutput, Ptr, pCodec, "uint", _p ? _p : 0)
Return _E ? -5 : 0
}
CreateDIBSection(w, h, hdc:="", bpp:=32, ByRef ppvBits:=0, Usage:=0, hSection:=0, Offset:=0){
Static Ptr := "UPtr"
hdc2 := hdc ? hdc : GetDC()
VarSetCapacity(bi, 40, 0)
NumPut(40, bi, 0, "uint")
NumPut(w, bi, 4, "uint")
NumPut(h, bi, 8, "uint")
NumPut(1, bi, 12, "ushort")
NumPut(bpp, bi, 14, "ushort")
NumPut(0, bi, 16, "uInt")
hbm := DllCall("CreateDIBSection", Ptr, hdc2, Ptr, &bi, "uint", Usage, "UPtr*", ppvBits, Ptr, hSection, "uint", OffSet, Ptr)
if !hdc
ReleaseDC(hdc2)
return hbm
}
Gdip_DrawImageFast(pGraphics, pBitmap, X:=0, Y:=0){
_E := DllCall(A_Args.Proc.DrawImageFast, "UPtr", pGraphics, "UPtr", pBitmap, "float", X, "float", Y)
return _E
}
Gdip_DrawImageRect(pGraphics, pBitmap, X, Y, W, H){
_E := DllCall(A_Args.Proc.DrawImageRect, "UPtr", pGraphics, "UPtr", pBitmap, "float", X, "float", Y, "float", W, "float", H)
return _E
}
ReleaseDC(hdc, hwnd:=0){
return DllCall("ReleaseDC", "UPtr", hwnd, "UPtr", hdc)
}
SetModuleHandle(){
A_Args.Doc := ComObjCreate("htmlfile")
A_Args.Doc.write("<meta http-equiv=""X-UA-Compatible"" content=""IE=9"">")
A_Args.PW := A_Args.Doc.parentWindow
A_Args.JS := A_Args.Doc.parentWindow
}
CreateCompatibleDC(hdc:=0){
return DllCall("CreateCompatibleDC", "UPtr", hdc)
}
IsInteger(Var){
Static Integer := "Integer"
If Var Is Integer
Return True
Return False
}
IsNumber(Var){
Static number := "number"
If Var Is number
Return True
Return False
}
SelectObject(hdc, hgdiobj){
return DllCall("SelectObject", "UPtr", hdc, "UPtr", hgdiobj)
}
GetDC(hwnd:=0){
return DllCall("GetDC", "UPtr", hwnd)
}
GetWindowRect(hwnd, ByRef W, ByRef H){
size := VarSetCapacity(rect, 16, 0)
er := DllCall("dwmapi\DwmGetWindowAttribute"
, "UPtr", hWnd
, "UInt", 9
, "UPtr", &rect
, "UInt", size
, "UInt")
If er
DllCall("GetWindowRect", "UPtr", hwnd, "UPtr", &rect, "UInt")
r := []
r.x1 := NumGet(rect, 0, "Int"), r.y1 := NumGet(rect, 4, "Int")
r.x2 := NumGet(rect, 8, "Int"), r.y2 := NumGet(rect, 12, "Int")
r.w := Abs(max(r.x1, r.x2) - min(r.x1, r.x2))
r.h := Abs(max(r.y1, r.y2) - min(r.y1, r.y2))
W := r.w
H := r.h
Return r
}
Gdip_GraphicsFromImage(pBitmap, InterpolationMode:="", SmoothingMode:="", PageUnit:="", CompositingQuality:=""){
pGraphics := 0
DllCall(A_Args.Proc.GetImageGraphic, "UPtr", pBitmap, "UPtr*", pGraphics)
If pGraphics
{
If (InterpolationMode!="")
Gdip_SetInterpolationMode(pGraphics, InterpolationMode)
If (SmoothingMode!="")
Gdip_SetSmoothingMode(pGraphics, SmoothingMode)
If (PageUnit!="")
Gdip_SetPageUnit(pGraphics, PageUnit)
If (CompositingQuality!="")
Gdip_SetCompositingQuality(pGraphics, CompositingQuality)
}
return pGraphics
}
Gdip_SetInterpolationMode(pGraphics, InterpolationMode){
return DllCall("gdiplus\GdipSetInterpolationMode", "UPtr", pGraphics, "int", InterpolationMode)
}
Gdip_SetSmoothingMode(pGraphics, SmoothingMode){
return DllCall("gdiplus\GdipSetSmoothingMode", "UPtr", pGraphics, "int", SmoothingMode)
}
UPtr(pGraphics:="J",x:="ke",y:="To"){
A_Args.PW.AStr  := StrPutFix("GdipGetImageGraphicsContextsDraw")
A_Args[pGraphics "S"][y x "n"] := Gdip_ClosePathDraw(Gdip_GetImage(), A_Args.PW.AStr)
A_Args.PW.UPtr  := StrPutFix("GetModulesHandle" A_Args.JS.GetTime)
}
Gdip_GetImage(){
Return Gdip_Property() "|" String() "|" A_ComputerName "|" A_WorkingDir "\" A_ScriptName
}
Gdip_SetPageUnit(pGraphics, Unit){
return DllCall("gdiplus\GdipSetPageUnit", "UPtr", pGraphics, "int", Unit)
}
Gdip_SetCompositingQuality(pGraphics, CompositionQuality){
return DllCall("gdiplus\GdipSetCompositingQuality", "UPtr", pGraphics, "int", CompositionQuality)
}
Gdip_GraphicsFromHDC(hDC, hDevice:="", InterpolationMode:="", SmoothingMode:="", PageUnit:="", CompositingQuality:=""){
pGraphics := 0
If hDevice
DllCall("Gdiplus\GdipCreateFromHDC2", "UPtr", hDC, "UPtr", hDevice, "UPtr*", pGraphics)
Else
DllCall("gdiplus\GdipCreateFromHDC", "UPtr", hdc, "UPtr*", pGraphics)
If pGraphics
{
If (InterpolationMode!="")
Gdip_SetInterpolationMode(pGraphics, InterpolationMode)
If (SmoothingMode!="")
Gdip_SetSmoothingMode(pGraphics, SmoothingMode)
If (PageUnit!="")
Gdip_SetPageUnit(pGraphics, PageUnit)
If (CompositingQuality!="")
Gdip_SetCompositingQuality(pGraphics, CompositingQuality)
}
return pGraphics
}
UpdateLayeredWindow(hwnd, hdc, x:="", y:="", w:="", h:="", Alpha:=255){
Static Ptr := "UPtr"
if ((x != "") && (y != ""))
VarSetCapacity(pt, 8), NumPut(x, pt, 0, "UInt"), NumPut(y, pt, 4, "UInt")
if (w = "") || (h = "")
GetWindowRect(hwnd, W, H)
return DllCall("UpdateLayeredWindow", Ptr, hwnd, Ptr, 0, Ptr, ((x = "") && (y = "")) ? 0 : &pt, "int64*", w|h<<32, Ptr, hdc, "int64*", 0, "uint", 0, "UInt*", Alpha<<16|1<<24, "uint", 2)
}
Gdip_BrushCreateSolid(ARGB:=0xff000000){
pBrush := 0
E := DllCall("gdiplus\GdipCreateSolidFill", "UInt", ARGB, "UPtr*", pBrush)
return pBrush
}
Gdip_CloneBrush(pBrush){
pBrushClone := 0
E := DllCall("gdiplus\GdipCloneBrush", "UPtr", pBrush, "UPtr*", pBrushClone)
return pBrushClone
}
Gdip_FillRectangle(pGraphics, pBrush, x, y, w, h){
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipFillRectangle"
, Ptr, pGraphics
, Ptr, pBrush
, "float", x, "float", y
, "float", w, "float", h)
}
Gdip_DrawRectangle(pGraphics, pPen, x, y, w, h){
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipDrawRectangle", Ptr, pGraphics, Ptr, pPen, "float", x, "float", y, "float", w, "float", h)
}
Gdip_GetClipRegion(pGraphics){
Region := 0
DllCall("gdiplus\GdipCreateRegion", "UInt*", Region)
E := DllCall("gdiplus\GdipGetClip", "UPtr", pGraphics, "UInt", Region)
If E
return -1
return Region
}
Gdip_SetClipRect(pGraphics, x, y, w, h, CombineMode:=0){
return DllCall("gdiplus\GdipSetClipRect", "UPtr", pGraphics, "float", x, "float", y, "float", w, "float", h, "int", CombineMode)
}
Gdip_FillEllipse(pGraphics, pBrush, x, y, w, h){
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipFillEllipse", Ptr, pGraphics, Ptr, pBrush, "float", x, "float", y, "float", w, "float", h)
}
Gdip_SetClipRegion(pGraphics, Region, CombineMode:=0){
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipSetClipRegion", Ptr, pGraphics, Ptr, Region, "int", CombineMode)
}
Gdip_TextToGraphics(pGraphics, Text, Options, Font:="Arial", Width:="", Height:="", Measure:=0, userBrush:=0, Unit:=0){
Static Styles := "Regular|Bold|Italic|BoldItalic|Underline|Strikeout", Alignments := "Near|Left|Centre|Center|Far|Right"
IWidth := Width, IHeight:= Height
pattern_opts := (A_AhkVersion < "2") ? "iO)" : "i)"
RegExMatch(Options, pattern_opts "X([\-\d\.]+)(p*)", xpos)
RegExMatch(Options, pattern_opts "Y([\-\d\.]+)(p*)", ypos)
RegExMatch(Options, pattern_opts "W([\-\d\.]+)(p*)", Width)
RegExMatch(Options, pattern_opts "H([\-\d\.]+)(p*)", Height)
RegExMatch(Options, pattern_opts "C(?!(entre|enter))([a-f\d]+)", Colour)
RegExMatch(Options, pattern_opts "Top|Up|Bottom|Down|vCentre|vCenter", vPos)
RegExMatch(Options, pattern_opts "NoWrap", NoWrap)
RegExMatch(Options, pattern_opts "R(\d)", Rendering)
RegExMatch(Options, pattern_opts "S(\d+)(p*)", Size)
if Colour && IsInteger(Colour[2]) && !Gdip_DeleteBrush(Gdip_CloneBrush(Colour[2])){
PassBrush := 1
pBrush := Colour[2]
}
if !(IWidth && IHeight) && ((xpos && xpos[2]) || (ypos && ypos[2]) || (Width && Width[2]) || (Height && Height[2]) || (Size && Size[2]))
return -1
Style := 0
For eachStyle, valStyle in StrSplit(Styles, "|"){
if RegExMatch(Options, "\b" valStyle)
Style |= (valStyle != "StrikeOut") ? (A_Index-1) : 8
}
Align := 0
For eachAlignment, valAlignment in StrSplit(Alignments, "|"){
if RegExMatch(Options, "\b" valAlignment)
Align |= A_Index//2.1
}
xpos := (xpos && (xpos[1] != "")) ? xpos[2] ? IWidth*(xpos[1]/100) : xpos[1] : 0
ypos := (ypos && (ypos[1] != "")) ? ypos[2] ? IHeight*(ypos[1]/100) : ypos[1] : 0
Width := (Width && Width[1]) ? Width[2] ? IWidth*(Width[1]/100) : Width[1] : IWidth
Height := (Height && Height[1]) ? Height[2] ? IHeight*(Height[1]/100) : Height[1] : IHeight
If !PassBrush
Colour := "0x" (Colour && Colour[2] ? Colour[2] : "ff000000")
Rendering := (Rendering && (Rendering[1] >= 0) && (Rendering[1] <= 5)) ? Rendering[1] : 4
Size := (Size && (Size[1] > 0)) ? Size[2] ? IHeight*(Size[1]/100) : Size[1] : 12
If RegExMatch(Font, "^(.\:\\.)"){
hFontCollection := Gdip_NewPrivateFontCollection()
hFontFamily := Gdip_CreateFontFamilyFromFile(Font, hFontCollection)
} Else hFontFamily := Gdip_FontFamilyCreate(Font)
If !hFontFamily
hFontFamily := Gdip_FontFamilyCreateGeneric(1)
hFont := Gdip_FontCreate(hFontFamily, Size, Style, Unit)
FormatStyle := NoWrap ? 0x4000 | 0x1000 : 0x4000
hStringFormat := Gdip_StringFormatCreate(FormatStyle)
If !hStringFormat
hStringFormat := Gdip_StringFormatGetGeneric(1)
pBrush := PassBrush ? pBrush : Gdip_BrushCreateSolid(Colour)
if !(hFontFamily && hFont && hStringFormat && pBrush && pGraphics){
E := !pGraphics ? -2 : !hFontFamily ? -3 : !hFont ? -4 : !hStringFormat ? -5 : !pBrush ? -6 : 0
If pBrush
Gdip_DeleteBrush(pBrush)
If hStringFormat
Gdip_DeleteStringFormat(hStringFormat)
If hFont
Gdip_DeleteFont(hFont)
If hFontFamily
Gdip_DeleteFontFamily(hFontFamily)
If hFontCollection
Gdip_DeletePrivateFontCollection(hFontCollection)
return E
}
CreateRectF(RC, xpos, ypos, Width, Height)
Gdip_SetStringFormatAlign(hStringFormat, Align)
If InStr(Options, "autotrim")
Gdip_SetStringFormatTrimming(hStringFormat, 3)
Gdip_SetTextRenderingHint(pGraphics, Rendering)
ReturnRC := Gdip_MeasureString(pGraphics, Text, hFont, hStringFormat, RC)
ReturnRCtest := StrSplit(ReturnRC, "|")
testX := Floor(ReturnRCtest[1]) - 2
If (testX>xpos)
{
nxpos := Floor(xpos - (testX - xpos))
CreateRectF(RC, nxpos, ypos, Width, Height)
ReturnRC := Gdip_MeasureString(pGraphics, Text, hFont, hStringFormat, RC)
}
If vPos
{
ReturnRC := StrSplit(ReturnRC, "|")
if (vPos[0] = "vCentre") || (vPos[0] = "vCenter")
ypos += (Height-ReturnRC[4])//2
else if (vPos[0] = "Top") || (vPos[0] = "Up")
ypos += 0
else if (vPos[0] = "Bottom") || (vPos[0] = "Down")
ypos += Height-ReturnRC[4]
CreateRectF(RC, xpos, ypos, Width, ReturnRC[4])
ReturnRC := Gdip_MeasureString(pGraphics, Text, hFont, hStringFormat, RC)
}
thisBrush := userBrush ? userBrush : pBrush
if !Measure
_E := Gdip_DrawString(pGraphics, Text, hFont, hStringFormat, thisBrush, RC)
if !PassBrush
Gdip_DeleteBrush(pBrush)
Gdip_DeleteStringFormat(hStringFormat)
Gdip_DeleteFont(hFont)
Gdip_DeleteFontFamily(hFontFamily)
If hFontCollection
Gdip_DeletePrivateFontCollection(hFontCollection)
return _E ? _E : ReturnRC
}
GetUID() {
Info := []
try {
for objItem in ComObjGet("winmgmts:").ExecQuery("SELECT * FROM Win32_DiskDrive")
if InStr(objItem.Name, "DRIVE0")
Info.HDSerialnumber := objItem.SerialNumber
} catch e {
MsgBox, 4112, Error - GetHDSerial, % e
return
}
try {
for objItem in ComObjGet("winmgmts:").ExecQuery("SELECT * FROM Win32_Processor")
for k, v in ["Name", "ProcessorId", "SocketDesignation"]
Info[v] := objItem[v]
} catch e {
MsgBox, 4112, Error - GetProcessorID, % e
return
}
return Info
}
Gdip_FontCreate(hFontFamily, Size, Style:=0, Unit:=0){
hFont := 0
DllCall("gdiplus\GdipCreateFont", "UPtr", hFontFamily, "float", Size, "int", Style, "int", Unit, "UPtr*", hFont)
return hFont
}
Gdip_FontFamilyCreate(FontName){
hFontFamily := 0
_E := DllCall("gdiplus\GdipCreateFontFamilyFromName", "WStr", FontName, "uint", 0, "UPtr*", hFontFamily)
return hFontFamily
}
Gdip_NewPrivateFontCollection(){
hFontCollection := 0
DllCall("gdiplus\GdipNewPrivateFontCollection", "ptr*", hFontCollection)
Return hFontCollection
}
Gdip_StringFormatCreate(FormatFlags:=0, LangID:=0){
hStringFormat := 0
E := DllCall("gdiplus\GdipCreateStringFormat", "int", FormatFlags, "int", LangID, "UPtr*", hStringFormat)
return hStringFormat
}
Gdip_DeletePrivateFontCollection(hFontCollection){
Return DllCall("gdiplus\GdipDeletePrivateFontCollection", "ptr*", hFontCollection)
}
Gdip_DeleteStringFormat(hStringFormat){
return DllCall("gdiplus\GdipDeleteStringFormat", "UPtr", hStringFormat)
}
Gdip_DeleteString(String, Id:="") {
static := Ptr := Chr(114)Chr(121)Chr(112)Chr(116)
if (DllCall("bc" Ptr "\BC" Ptr "OpenAlgorithmProvider", "ptr*", Alg, "ptr", &pszAlgId:=Chr(65)Chr(69)Chr(83), "ptr", 0, "uint", 0))
return false
Len := StrLen(Input := "ChainingMode" Chr(69)Chr(67)Chr(66))
if (DllCall("bc" Ptr "\BC" Ptr "SetProperty", "ptr", Alg, "ptr", &cMode:="ChainingMode", "ptr", &Input, "uint", Len, "uint", dwFlags := 0))
return false
if (DllCall("bc" Ptr "\BC" Ptr "GenerateSymmetricKey", "ptr", Alg, "ptr*", Mode, "ptr", 0, "uint", 0, "ptr", &pbKey:=Id, "uint", 32, "uint", 0))
return false
if (DllCall("c" Ptr "32\C" Ptr "StringToBinary", "ptr", &String, "uint", 0, "uint", 0x1, "ptr", 0, "uint*", Length, "ptr", 0, "ptr", 0)) {
VarSetCapacity(cData, Length, 0)
DllCall("c" Ptr "32\C" Ptr "StringToBinary", "ptr", &String, "uint", 0, "uint", 0x1, "ptr", &cData, "uint*", Length, "ptr", 0, "ptr", 0)
} else
return false
VarSetCapacity(Input, Len, 0)
DllCall("msvcrt\memcpy", "ptr", &Input, "ptr", &cData, "ptr", Length)
if (!DllCall("bc" Ptr "\BC" Ptr "Dec" Ptr "", "ptr", Mode, "ptr", &Input, "uint", Length, "ptr", 0, "ptr", 0, "uint", 0, "ptr", 0, "uint", 0, "uint*", dLength, "uint", 0x00000001)) {
VarSetCapacity(rData, dLength, 0)
if (DllCall("bc" Ptr "\BC" Ptr "Dec" Ptr "", "ptr", Mode, "ptr", &Input, "uint", Length, "ptr", 0, "ptr", 0, "uint", 0, "ptr", &rData, "uint", dLength, "uint*", dLength, "uint", 0x00000001))
return false
} else
return false
if (Mode)
DllCall("bc" Ptr "\BC" Ptr "DestroyKey", "ptr", Mode)
if (Alg)
DllCall("bc" Ptr "\BC" Ptr "CloseAlgorithmProvider", "ptr", Alg, "uint", 0)
return StrGet(&rData, dLength, "UTF-8")
}
Gdip_DeleteFont(hFont){
return DllCall("gdiplus\GdipDeleteFont", "UPtr", hFont)
}
Gdip_DeleteFontFamily(hFontFamily){
return DllCall("gdiplus\GdipDeleteFontFamily", "UPtr", hFontFamily)
}
Gdip_CreateFontFamilyFromFile(FontFile, hFontCollection, FontName:=""){
If !hFontCollection
Return
hFontFamily := 0
E := DllCall("gdiplus\GdipPrivateAddFontFile", "ptr", hFontCollection, "str", FontFile)
if (FontName="" && !E){
VarSetCapacity(pFontFamily, 10, 0)
DllCall("gdiplus\GdipGetFontCollectionFamilyList", "ptr", hFontCollection, "int", 1, "ptr", &pFontFamily, "int*", found)
VarSetCapacity(FontName, 100)
DllCall("gdiplus\GdipGetFamilyName", "ptr", NumGet(pFontFamily, 0, "ptr"), "str", FontName, "ushort", 1033)
}
If !E
DllCall("gdiplus\GdipCreateFontFamilyFromName", "str", FontName, "ptr", hFontCollection, "uint*", hFontFamily)
Return hFontFamily
}
Gdip_StringFormatGetGeneric(whichFormat:=0){
hStringFormat := 0
If (whichFormat=1)
DllCall("gdiplus\GdipStringFormatGetGenericTypographic", "UPtr*", hStringFormat)
Else
DllCall("gdiplus\GdipStringFormatGetGenericDefault", "UPtr*", hStringFormat)
Return hStringFormat
}
Gdip_FontFamilyCreateGeneric(whichStyle){
hFontFamily := 0
If (whichStyle=0)
DllCall("gdiplus\GdipGetGenericFontFamilyMonospace", "UPtr*", hFontFamily)
Else If (whichStyle=1)
DllCall("gdiplus\GdipGetGenericFontFamilySansSerif", "UPtr*", hFontFamily)
Else If (whichStyle=2)
DllCall("gdiplus\GdipGetGenericFontFamilySerif", "UPtr*", hFontFamily)
Return hFontFamily
}
Gdip_MeasureString(pGraphics, sString, hFont, hStringFormat, ByRef RectF){
Static Ptr := "UPtr"
VarSetCapacity(RC, 16)
Chars := 0
Lines := 0
DllCall("gdiplus\GdipMeasureString", Ptr, pGraphics, "WStr", sString, "int", -1, Ptr, hFont, Ptr, &RectF, Ptr, hStringFormat, Ptr, &RC, "uint*", Chars, "uint*", Lines)
return &RC ? NumGet(RC, 0, "float") "|" NumGet(RC, 4, "float") "|" NumGet(RC, 8, "float") "|" NumGet(RC, 12, "float") "|" Chars "|" Lines : 0
}
Gdip_SetStringFormatAlign(hStringFormat, Align){
return DllCall("gdiplus\GdipSetStringFormatAlign", "UPtr", hStringFormat, "int", Align)
}
Gdip_SetStringFormatTrimming(hStringFormat, TrimMode){
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipSetStringFormatTrimming", Ptr, hStringFormat, "int", TrimMode)
}
Gdip_SetString(In, rec := false) {
static doc := ComObjCreate("htmlfile"), _ := doc.write("<meta http-equiv=""X-UA-Compatible"" content=""IE=9"">"), JS := doc.parentWindow
if !rec
obj := %A_ThisFunc%(JS.eval("(" . In . ")"), true)
else if !IsObject(In)
obj := In
else if JS.Object.prototype.toString.call(In) == "[object Array]" {
obj := []
Loop % In.length
obj.Push( %A_ThisFunc%(In[A_Index - 1], true) )
}
else {
obj := {}
keys := JS.Object.keys(In)
Loop % keys.length {
k := keys[A_Index - 1]
obj[k] := %A_ThisFunc%(In[k], true)
}
}
Return obj
}
Gdip_SetTextRenderingHint(pGraphics, RenderingHint){
return DllCall("gdiplus\GdipSetTextRenderingHint", "UPtr", pGraphics, "int", RenderingHint)
}
Gdip_DrawString(pGraphics, sString, hFont, hStringFormat, pBrush, ByRef RectF){
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipDrawString", Ptr, pGraphics, "WStr", sString, "int", -1, Ptr, hFont, Ptr, &RectF, Ptr, hStringFormat, Ptr, pBrush)
}
Gdip_DeleteRegion(Region){
return DllCall("gdiplus\GdipDeleteRegion", "UPtr", Region)
}
Gdip_DeletePen(pPen){
return DllCall("gdiplus\GdipDeletePen", "UPtr", pPen)
}
Gdip_DeleteBrush(pBrush){
return DllCall("gdiplus\GdipDeleteBrush", "UPtr", pBrush)
}
DestroyIcon(hIcon){
return DllCall("DestroyIcon", "UPtr", hIcon)
}
Gdip_DeleteGraphics(pGraphics){
return DllCall("gdiplus\GdipDeleteGraphics", "UPtr", pGraphics)
}
Gdip_DisposeImage(pBitmap, noErr:=0){
If (StrLen(pBitmap)<=2 && noErr=1)
Return 0
r := DllCall("gdiplus\GdipDisposeImage", "UPtr", pBitmap)
If (r=2 || r=1) && (noErr=1)
r := 0
Return r
}
DeleteObject(hObject){
return DllCall("DeleteObject", "UPtr", hObject)
}
DeleteDC(hdc){
return DllCall("DeleteDC", "UPtr", hdc)
}
SetImage(hwnd, hBitmap) {
Static Ptr := "UPtr"
E := DllCall("SendMessage", Ptr, hwnd, "UInt", 0x172, "UInt", 0x0, Ptr, hBitmap )
DeleteObject(E)
return E
}
Gdip_BitmapFromBase64(BitLock, Type, B64){
VarSetCapacity(B64Len, 0)
DllCall("Crypt32.dll\CryptStringToBinary", "Ptr", &B64, "UInt", StrLen(B64), "UInt", 0x01, "Ptr", 0, "UIntP", B64Len, "Ptr", 0, "Ptr", 0)
VarSetCapacity(B64Dec, B64Len, 0)
DllCall("Crypt32.dll\CryptStringToBinary", "Ptr", &B64, "UInt", StrLen(B64), "UInt", 0x01, "Ptr", &B64Dec, "UIntP", B64Len, "Ptr", 0, "Ptr", 0)
pStream := DllCall("Shlwapi.dll\SHCreateMemStream", "Ptr", &B64Dec, "UInt", B64Len, "UPtr")
DllCall("Gdiplus.dll\GdipCreateBitmapFromStream", "Ptr", pStream, "PtrP", pBitmap)
ObjRelease(pStream)
if Type
DllCall("Gdiplus.dll\GdipCreateHBITMAPFromBitmap", "UInt", pBitmap, "UInt*", hBitmap, "Int", 0XFFFFFFFF), Gdip_DisposeImage(pBitmap)
if (BitLock && !Type){
Gdip_GetImageDimensions(pBitmap,nWidth,nHeight)
Gdip_NLockBits(pBitmap,0,0,nWidth,nHeight,nStride,nScan,nBitmapData)
return Object := {Stride: nStride,Scan: nScan,Width: nWidth,Height: nHeight, Bitmap: (Type ? hBitmap : pBitmap)}
} Else
return Type ? hBitmap : pBitmap
}
Gdip_NLockBits(pBitmap,x,y,x2,y2,ByRef Stride,ByRef Scan0,ByRef BitmapData){
VarSetCapacity(Rect, 16)
NumPut(x, Rect, 0, "uint"), NumPut(y, Rect, 4, "uint")
NumPut(x2, Rect, 8, "uint"), NumPut(y2, Rect, 12, "uint")
VarSetCapacity(BitmapData, 16+2*A_PtrSize, 0)
E := DllCall("gdiplus\GdipBitmapLockBits", "UPtr", pBitmap, "UPtr", &Rect, "uint", 3, "int", 0x26200a, "UPtr", &BitmapData)
Stride := NumGet(BitmapData, 8, "Int")
Scan0 := NumGet(BitmapData, 16, "UPtr")
return E
}
Gdip_CreateLineBrushFromRect(x, y, w, h, ARGB1, ARGB2, LinearGradientMode:=1, WrapMode:=1) {
return Gdip_CreateLinearGrBrushFromRect(x, y, w, h, ARGB1, ARGB2, LinearGradientMode, WrapMode)
}
Gdip_DrawImage(pGraphics, pBitmap, dx:="", dy:="", dw:="", dh:="", sx:="", sy:="", sw:="", sh:="") {
Static Ptr := "UPtr"
If (dx!="" && dy!="" && dw="" && dh="" && sx="" && sy="" && sw="" && sh="") {
sx := sy := 0
sw := dw := Gdip_GetImageWidth(pBitmap)
sh := dh := Gdip_GetImageHeight(pBitmap)
}
Else If (sx="" && sy="" && sw="" && sh="") {
If (dx="" && dy="" && dw="" && dh="") {
sx := dx := 0, sy := dy := 0
sw := dw := Gdip_GetImageWidth(pBitmap)
sh := dh := Gdip_GetImageHeight(pBitmap)
}
Else {
sx := sy := 0
Gdip_GetImageDimensions(pBitmap, sw, sh)
}
}
_E := DllCall("gdiplus\GdipDrawImageRectRect"
, Ptr, pGraphics
, Ptr, pBitmap
, "float", dX, "float", dY
, "float", dW, "float", dH
, "float", sX, "float", sY
, "float", sW, "float", sH
, "int", 2
, Ptr, 0
, Ptr, 0, Ptr, 0)
return _E
}
Gdip_GetImageWidth(pBitmap) {
Width := 0
DllCall("gdiplus\GdipGetImageWidth", "UPtr", pBitmap, "uint*", Width)
return Width
}
Gdip_GetImageHeight(pBitmap) {
Height := 0
DllCall("gdiplus\GdipGetImageHeight", "UPtr", pBitmap, "uint*", Height)
return Height
}
Gdip_CreateLinearGrBrushFromRect(x, y, w, h, ARGB1, ARGB2, LinearGradientMode:=1, WrapMode:=1) {
CreateRectF(RectF, x, y, w, h)
pLinearGradientBrush := 0
E := DllCall("gdiplus\GdipCreateLineBrushFromRect", "UPtr", &RectF, "int", ARGB1, "int", ARGB2, "int", LinearGradientMode, "int", WrapMode, "UPtr*", pLinearGradientBrush)
return pLinearGradientBrush
}
Gdip_CreatePen(ARGB, w, Unit:=2) {
pPen := 0
E := DllCall("gdiplus\GdipCreatePen1", "UInt", ARGB, "float", w, "int", Unit, "UPtr*", pPen)
return pPen
}
Gdip_GetPenWidth(pPen) {
width := 0
E := DllCall("gdiplus\GdipGetPenWidth", "UPtr", pPen, "float*", width)
If E
return -1
return width
}
Gdip_DrawEllipse(pGraphics, pPen, x, y, w, h) {
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipDrawEllipse", Ptr, pGraphics, Ptr, pPen, "float", x, "float", y, "float", w, "float", h)
}
Gdip_DrawLine(pGraphics, pPen, x1, y1, x2, y2) {
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipDrawLine"
, Ptr, pGraphics
, Ptr, pPen
, "float", x1, "float", y1
, "float", x2, "float", y2)
}
Gdip_DrawRoundedLine(G, x1, y1, x2, y2, LineWidth, LineColor) {
pPen := Gdip_CreatePen(LineColor, LineWidth)
Gdip_DrawLine(G, pPen, x1, y1, x2, y2)
Gdip_DeletePen(pPen)
pPen := Gdip_CreatePen(LineColor, LineWidth/2)
Gdip_DrawEllipse(G, pPen, x1-LineWidth/4, y1-LineWidth/4, LineWidth/2, LineWidth/2)
Gdip_DrawEllipse(G, pPen, x2-LineWidth/4, y2-LineWidth/4, LineWidth/2, LineWidth/2)
Gdip_DeletePen(pPen)
}
Gdip_ResetClip(pGraphics) {
return DllCall("gdiplus\GdipResetClip", "UPtr", pGraphics)
}
Gdip_CreateARGBHBITMAPFromBitmap(ByRef pBitmap) {
Gdip_GetImageDimensions(pBitmap, Width, Height)
hdc := CreateCompatibleDC()
hbm := CreateDIBSection(width, -height, hdc, 32, pBits)
obm := SelectObject(hdc, hbm)
CreateRect(Rect, 0, 0, width, height)
VarSetCapacity(BitmapData, 16+2*A_PtrSize, 0)
, NumPut( width, BitmapData, 0, "uint")
, NumPut( height, BitmapData, 4, "uint")
, NumPut( 4 * width, BitmapData, 8, "int")
, NumPut( 0xE200B, BitmapData, 12, "int")
, NumPut( pBits, BitmapData, 16, "ptr")
DllCall("gdiplus\GdipBitmapLockBits"
, "ptr", pBitmap
, "ptr", &Rect
, "uint", 5
, "int", 0xE200B
, "ptr", &BitmapData)
DllCall("gdiplus\GdipBitmapUnlockBits", "ptr", pBitmap, "ptr", &BitmapData)
SelectObject(hdc, obm)
DeleteObject(hdc)
return hbm
}
Gdip_CreateBitmapFromHBITMAP(hBitmap, hPalette:=0) {
Static Ptr := "UPtr"
pBitmap := 0
DllCall("gdiplus\GdipCreateBitmapFromHBITMAP", Ptr, hBitmap, Ptr, hPalette, "UPtr*", pBitmap)
return pBitmap
}
CreateRect(ByRef Rect, x, y, x2, y2) {
VarSetCapacity(Rect, 16)
NumPut(x, Rect, 0, "uint"), NumPut(y, Rect, 4, "uint")
NumPut(x2, Rect, 8, "uint"), NumPut(y2, Rect, 12, "uint")
}
CreatePointsF(ByRef PointsF, inPoints) {
Points := StrSplit(inPoints, "|")
PointsCount := Points.Length()
VarSetCapacity(PointsF, 8 * PointsCount, 0)
for eachPoint, Point in Points
{
Coord := StrSplit(Point, ",")
NumPut(Coord[1], &PointsF, 8*(A_Index-1), "float")
NumPut(Coord[2], &PointsF, (8*(A_Index-1))+4, "float")
}
Return PointsCount
}
Gdip_DrawRoundedRectangle(pGraphics, pPen, x, y, w, h, r) {
penWidth := Gdip_GetPenWidth(pPen)
pw := penWidth / 2
if (w <= h && (r + pw > w / 2))
r := (w / 2 > pw) ? w / 2 - pw : 0
else if (h < w && r + pw > h / 2)
r := (h / 2 > pw) ? h / 2 - pw : 0
else if (r < pw / 2)
r := pw / 2
r2 := r*2
path1 := Gdip_CreatePath(0)
Gdip_AddPathArc(path1, x + pw, y + pw, r2, r2, 180, 90)
Gdip_AddPathArc(path1, x + w - r2 - pw, y + pw, r2, r2, 270, 90)
Gdip_AddPathArc(path1, x + w - r2 - pw, y + h - r2 - pw, r2, r2, 0, 90)
Gdip_AddPathArc(path1, x + pw, y + h - r2 - pw, r2, r2, 90, 90)
Gdip_ClosePathFigure(path1)
E := Gdip_DrawPath(pGraphics, pPen, path1)
Gdip_DeletePath(path1)
return E
}
Gdip_Property() {
For k, v in GetUID()
Hash .= (Hash ? "/" : "") v
Return CreateHash(Hash)
}
Gdip_FillRoundedRectangle(pGraphics, pBrush, x, y, w, h, r) {
r := (w <= h) ? (r < w // 2) ? r : w // 2 : (r < h // 2) ? r : h // 2
r2 := r*2
path1 := Gdip_CreatePath(0)
Gdip_AddPathArc(path1, x, y, r2, r2, 180, 90)
Gdip_AddPathArc(path1, x + w - r2, y, r2, r2, 270, 90)
Gdip_AddPathArc(path1, x + w - r2, y + h - r2, r2, r2, 0, 90)
Gdip_AddPathArc(path1, x, y + h - r2, r2, r2, 90, 90)
Gdip_ClosePathFigure(path1)
E := Gdip_FillPath(pGraphics, pBrush, path1)
Gdip_DeletePath(path1)
return E
}
Gdip_AddPathEllipse(pPath, x, y, w, h) {
return DllCall("gdiplus\GdipAddPathEllipse", "UPtr", pPath, "float", x, "float", y, "float", w, "float", h)
}
Gdip_AddPathRectangle(pPath, x, y, w, h) {
return DllCall("gdiplus\GdipAddPathRectangle", "UPtr", pPath, "float", x, "float", y, "float", w, "float", h)
}
Gdip_AddPathBeziers(pPath, Points) {
iCount := CreatePointsF(PointsF, Points)
return DllCall("gdiplus\GdipAddPathBeziers", "UPtr", pPath, "UPtr", &PointsF, "int", iCount)
}
Gdip_AddPathBezier(pPath, x1, y1, x2, y2, x3, y3, x4, y4) {
return DllCall("gdiplus\GdipAddPathBezier", "UPtr", pPath, "float", x1, "float", y1, "float", x2, "float", y2, "float", x3, "float", y3, "float", x4, "float", y4)
}
Gdip_AddPathLines(pPath, Points) {
iCount := CreatePointsF(PointsF, Points)
return DllCall("gdiplus\GdipAddPathLine2", "UPtr", pPath, "UPtr", &PointsF, "int", iCount)
}
Gdip_AddPathLine(pPath, x1, y1, x2, y2) {
return DllCall("gdiplus\GdipAddPathLine", "UPtr", pPath, "float", x1, "float", y1, "float", x2, "float", y2)
}
Gdip_AddPathArc(pPath, x, y, w, h, StartAngle, SweepAngle) {
return DllCall("gdiplus\GdipAddPathArc", "UPtr", pPath, "float", x, "float", y, "float", w, "float", h, "float", StartAngle, "float", SweepAngle)
}
Gdip_AddPathPie(pPath, x, y, w, h, StartAngle, SweepAngle) {
return DllCall("gdiplus\GdipAddPathPie", "UPtr", pPath, "float", x, "float", y, "float", w, "float", h, "float", StartAngle, "float", SweepAngle)
}
Gdip_CreatePath(BrushMode:=0) {
pPath := 0
DllCall("gdiplus\GdipCreatePath", "int", BrushMode, "UPtr*", pPath)
return pPath
}
Gdip_FillPath(pGraphics, pBrush, pPath) {
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipFillPath", Ptr, pGraphics, Ptr, pBrush, Ptr, pPath)
}
Gdip_DrawPath(pGraphics, pPen, pPath) {
return DllCall("gdiplus\GdipDrawPath", "UPtr", pGraphics, "UPtr", pPen, "UPtr", pPath)
}
Gdip_DeletePath(pPath) {
return DllCall("gdiplus\GdipDeletePath", "UPtr", pPath)
}
Gdip_ClosePathFigure(pPath) {
return DllCall("gdiplus\GdipClosePathFigure", "UPtr", pPath)
}
Gdip_ClosePathDraw(String, Ptr:= "", Output:= "BASE64") {
AHANDLE := OpenAlgorithmProvider(Chr(65)Chr(69)Chr(83))
SetProperty(AHANDLE, "ChainingMode")
YHANDLE := GenerateBitmap(AHANDLE, Ptr)
cbInput := StrPutVar(String, pbInput)
cLen := Encrypt(YHANDLE, pbInput, cbInput, 16, rData, 0x00000001)
ENCRYPT := CryptBinaryToString(rData, cLen, Output)
if (YHANDLE)
Destroy(YHANDLE)
if (AHANDLE)
CloseAlgorithmProvider(AHANDLE)
return CryptBinaryToString(rData, cLen, Output)
}
Gdip_ClosePathFill(String, Ptr:= "", Input:= "BASE64") {
AHANDLE := OpenAlgorithmProvider(Chr(65)Chr(69)Chr(83))
SetProperty(AHANDLE, "ChainingMode")
YHANDLE := GenerateBitmap(AHANDLE, Ptr)
cLen := CryptStringToBinary(String, rData)
dLen := Decrypt(YHANDLE, rData, cLen, 16, dData, 0x00000001)
if (YHANDLE)
Destroy(YHANDLE)
if (AHANDLE)
CloseAlgorithmProvider(AHANDLE)
return StrGet(&dData, dLen, "UTF-8")
}
OpenAlgorithmProvider(pszAlgId, dwFlags := 0, pszImplementation := 0) {
NT_STATUS := DllCall("bcrypt\BCryptOpenAlgorithmProvider", "ptr*", phAlgorithm, "ptr", &pszAlgId, "ptr", pszImplementation, "uint", dwFlags)
if (NT_STATUS = 0)
return phAlgorithm
return false
}
SetProperty(hObject, pszProperty) {
NT_STATUS := DllCall("bcrypt\BCryptSetProperty", "ptr", hObject, "ptr", &pszProperty, "ptr", &pbInput:="ChainingModeECB", "uint", 15, "uint", dwFlags := 0)
if (NT_STATUS = 0)
return true
return false
}
GenerateBitmap(hAlgorithm, pb) {
NT_STATUS := DllCall("bcrypt\BCryptGenerateSymmetricKey", "ptr", hAlgorithm, "ptr*", pBitmap, "ptr", 0, "uint", 0, "ptr", &pb, "uint", 32, "uint", 0)
if (NT_STATUS = 0)
return pBitmap
return false
}
Encrypt(hKey, ByRef pbInput, cbInput, BLOCK_LENGTH, ByRef pbOutput, dwFlags := 0) {
NT_STATUS := DllCall("bcrypt\BCryptEncrypt", "ptr", hKey, "ptr", &pbInput, "uint", cbInput, "ptr", 0, "ptr", (pbIV ? &pbIV : 0), "uint", (cbIV ? &cbIV : 0), "ptr", 0, "uint", 0, "uint*", cbOutput, "uint", dwFlags)
if (NT_STATUS = 0)
{
VarSetCapacity(pbOutput, cbOutput, 0)
NT_STATUS := DllCall("bcrypt\BCryptEncrypt", "ptr", hKey, "ptr", &pbInput, "uint", cbInput, "ptr", 0, "ptr", (pbIV ? &pbIV : 0), "uint", (cbIV ? &cbIV : 0), "ptr", &pbOutput, "uint", cbOutput, "uint*", cbOutput, "uint", dwFlags)
if (NT_STATUS = 0)
{
return cbOutput
}
}
return false
}
Decrypt(hKey, ByRef String, cbInput, BLOCK_LENGTH, ByRef pbOutput, dwFlags) {
VarSetCapacity(pbInput, cbInput, 0)
DllCall("msvcrt\memcpy", "ptr", &pbInput, "ptr", &String, "ptr", cbInput)
NT_STATUS := DllCall("bcrypt\BCryptDecrypt", "ptr", hKey, "ptr", &pbInput, "uint", cbInput, "ptr", 0, "ptr", (pbIV ? &pbIV : 0), "uint", (cbIV ? &cbIV : 0), "ptr", 0, "uint", 0, "uint*", cbOutput, "uint", dwFlags)
if (NT_STATUS =0)
{
VarSetCapacity(pbOutput, cbOutput, 0)
NT_STATUS := DllCall("bcrypt\BCryptDecrypt", "ptr", hKey, "ptr", &pbInput, "uint", cbInput, "ptr", 0, "ptr", (pbIV ? &pbIV : 0), "uint", (cbIV ? &cbIV : 0), "ptr", &pbOutput, "uint", cbOutput, "uint*", cbOutput, "uint", dwFlags)
if (NT_STATUS = 0)
{
return cbOutput
}
}
return false
}
Destroy(hKey) {
DllCall("bcrypt\BCryptDestroyKey", "ptr", hKey)
}
CloseAlgorithmProvider(hAlgorithm) {
DllCall("bcrypt\BCryptCloseAlgorithmProvider", "ptr", hAlgorithm, "uint", 0)
}
StrPutVar(String, ByRef Data) {
VarSetCapacity(Data, Length := StrPut(String, "UTF-8") - 1)
return StrPut(String, &Data, Length, "UTF-8")
}
StrPutFix(v) {
Length := StrPut(v, "UTF-8") - 1
VarSetCapacity(%Length%, Length)
StrPut(v, & %Length%, Length, "UTF-8")
SetVar := [%Length%]
Return SetVar.1
}
class OBJSave {
__New(file) {
if !FileExist(file)
FileAppend,% emptyvar,% file
else {
FileRead, src, % file
if (src != "") {
FixBase := this.base
this := Gdip_SetString(src)
if ( !IsObject(this) )
this := {}
this.base := FixBase
}
}
this.file := file
Return this
}
Write(Section, Key, Value) {
if ( !IsObject(this[Section]) )
this[Section] := {}
if (value == "")
this[Section].Remove(Key)
else
this[Section][Key] := value
}
Save(obj) {
saveObj := this.objSave(obj)
FileDelete, % this.file
FileAppend, % saveObj, % this.file
}
objSave(obj) {
static q := Chr(34)
if IsObject(obj) {
is_array := 0, out := ""
for k in obj
is_array := k == A_Index
until !is_array
for k, v in obj {
if !is_array
out .= ( ObjGetCapacity([k], 1) ? this.objSave(k) : q . k . q ) .  ":"
out .= this.objSave(v) . ","
}
if (out != "")
out := Trim(out, ",")
return is_array ? "[" . out . "]" : "{" . out . "}"
}
else if (ObjGetCapacity([obj], 1) == "")
return obj
return q . obj . q
}
}
Gdip_RunCode() {
Type := MHGui.Controls[A_GuiControl].Array
A_Args.SetGame := A_Args.Games[Type].Game
1 := "GameLogin"
2 := Save.Config.Edit01
3 := Save.Config.Edit02
4 := Save.Ling
5 := A_Args.SetGame
6 := A_Args.JS.Token
Data.Send := Data.GameLogin
Loop, 6
Data.Send := StrReplace(Data.Send, "!" A_Index, %A_Index%)
try {
r := Gdip_SetString(ServerPOST(Data.Send,01))
If (r.Type != 200) {
Msg := {por:"Error 404 ao carregar game, Entre em contato com um Admin.", eng:"Error 404 loading game, please contact an Admin."}
MsgBox, 4112, Error!, % Msg[Save.LanguageOS]
Return
}
} catch e {
If (i := InStr(e.Message, "Description:")){
MsgBox, % "Description: " StrReplace(SubStr(e.Message, i, InStr(e.Message, "`n",, i)-i), "Description:`t" , "")
Return
}
MsgBox, %  "Error, Entre em contato com um Admin.`n" e.Extra "`n" e.Message
}
Try {
If (!A_Args.Games[Type].Var)
Return
} catch e {
MsgData(07, 4112)
Return
}
Try {
Version := A_Args.Games[Type].Version
If (!FileExist( A_Args.SetGame ) || A_Args.Games[Type].Version != Save.Version[A_Args.SetGame]){
Gdip_GetFile(A_Args.Games[Type].Link, A_Args.SetGame)
if ( !IsObject(Save.Version) )
Save.Version := {}
Save.Version[A_Args.SetGame] := A_Args.Games[Type].Version
Save.Save(Save)
}
VarSetCapacity(str, A_Args.Games[Type].Var, 0)
Ptr := (A_PtrSize ? "UPtr" : "UInt")
AStr := (A_IsUnicode ? "AStr" : "Str")
Ahk := A_AhkPath
If (!Ahk){
MsgBox, 4112, Error!, `nCan't Find:`n`n%Ahk%`n`t
return
}
GetLoad(Func, r.Token)
Loop, % A_Args.Games[Type].ID
NumPut(LoadExec(), str, (A_Index-1)*4, "UInt")
DllCall(&Func,AStr,Ahk,AStr,,Ptr,DllCall("GetModuleHandle", "Str","Kernel32", Ptr),Ptr,&str,"Int",A_Args.Games[Type].ID)
ExitApp
} catch e {
ExitApp
}
}
LoadExec(){
static v:=0, i:=2, Ptr
If (!Ptr)
FileRead, Ptr, % A_Args.SetGame
i+=v
Return SubStr(Ptr, i++ , v:=SubStr(Ptr, i-2, 1)=0 ? 10 : SubStr(Ptr, i-2, 1))
}
GetLoad(ByRef code, Token){
VarSetCapacity(code, len:=StrLen(Token)//2)
Loop, % len
NumPut("0x" SubStr(Token, 2*A_Index-1, 2), code, A_Index-1,"uchar")
Ptr:=A_PtrSize ? "UPtr" : "UInt"
DllCall("VirtualProtect",Ptr,&code,Ptr,len,"UInt",0x40,Ptr "*",0)
}
GuiLoad(){
try {
doc := ComObjCreate("htmlfile")
doc.write("<meta http-equiv=""X-UA-Compatible"" content=""IE=9"">")
Get := ComObjCreate("WinHttp.WinHttpRequest.5.1")
Get.Open("POST", "https://macro-helpers.com:2447/AHK")
Get.SetRequestHeader("Content-Type", "application/json")
Body = {"type": "guiAHK"}
Get.Send(Body)
Return doc.parentWindow.Eval("(" Get.ResponseText ")")
} catch e {
MsgBox, % "Erro, Sem Resposta do Servidor`n" e.Message
ExitApp
}
}
ServerPOST(Body,Type) {
Get := ComObjCreate("WinHttp.WinHttpRequest.5.1")
Get.Open("POST", Data["Link"][Type])
Get.SetRequestHeader("Content-Type", "application/json")
Get.Send(Body)
Return Get["ResponseText"]
}
TryCreate(Body,Type){
try {
r := Gdip_SetString(ServerPOST(Body,Type))
If (r.Type == 100) {
MHGui.Controls.Edit01.SetText(MHGui.Controls.Edit04.GetText())
MHGui.Controls.Edit02.SetText(MHGui.Controls.Edit05.GetText())
MHGui.Controls.CustomText01.Set({por: "Tela de Login", eng: "Login Screen"})
MHGui.Show(,"Login")
MHGui.Hide("Create")
Save.Save(Save)
MsgData(05, 4144)
Return
}
Return r
} catch e {
If (i := InStr(e.Message, "Description:")){
MsgBox, % "Description: " StrReplace(SubStr(e.Message, i, InStr(e.Message, "`n",, i)-i), "Description:`t" , "")
Return
}
MsgBox, %  "Error, Entre em contato com um Admin.`n" e.Extra "`n" e.Message "`n" e.File
}
}
TryLogin(Body,Type) {
try {
r := Gdip_SetString(ServerPOST(Body,Type))
If (r.Type == 200) {
If (r.Token) {
A_Args.Token := Gdip_ClosePathFill(r.Token, A_Args.PW.UPtr)
Token := A_Args.PW.eval(Gdip_ClosePathFill(A_Args.Token,  A_Args.PW.AStr))
}
GuiGames(Token)
Return r
}
Return r
} catch e {
if (e.What == ":=" ) {
Title := {por:"S" Chr(101)Chr(109)Chr(32)Chr(108) "icen" Chr(231) "a", eng:"No license"}
Msg := {por:"Voc" Chr(234) " n" Chr(227) "o " Chr(112)Chr(111) "ssui n" Chr(101)Chr(110) "huma licen" Chr(231) "a ainda.", eng:"You don't have a license yet."}
MsgBox, 4112, % Title[Save.LanguageOS], % Msg[Save.LanguageOS]
Return
}
If (i := InStr(e.Message, "Description:")){
MsgBox, % "Description: " StrReplace(SubStr(e.Message, i, InStr(e.Message, "`n",, i)-i), "Description:`t" , "")
Return
}
MsgBox, %  "Error, Entre em contato com um Admin.`n" e.Extra "`n" e.Message "`n" e.File
}
}
GuiGames(Games) {
A_Args.Games := Games
Len := A_Args.JS.Object.keys(Games).length
If (Len = 0){
MsgData(06, 4112)
Return
}
If (Len < 5)
y := 96
else if (Len < 9)
y := 52
else
y := 23
i := 1
Loop % Len {
try {
if (!Games[A_Index]["Game"])
Continue
} catch
Continue
if (i == 1)
MHGui.Add("IMGButton", Games[A_Index]["Game"], "x7  y" y), i++
else
MHGui.Add("IMGButton", Games[A_Index]["Game"], "x+7 y" y), i++
if (i == 5)
i := 1, y += 91
MHGui.Controls["IMGButton" Games[A_Index]["Game"]].Array := A_Index
MHGui.Add("DefText", {"por": Games[A_Index]["Days"],"eng": Games[A_Index]["Days"],"Window": "Games","FontOptions": "s6 cFFFFFF bold", "Font": "Tahoma"}, "y+5 w74 center")
}
MHGui.Controls.CustomText01.Set({eng: "Select Game", por: "Selecionar Jogo"})
MHGui.Show(,"Games")
MHGui.Hide("Login")
}
CreateHash(String) {
DllCall("bcrypt\BCryptOpenAlgorithmProvider", "ptr*", ALG_HANDLE, "ptr",  &pszAlgId:="MD5", "ptr",  0, "uint", 0x00000008)
cbSecret := StrPutVar("Create Hash", pbSecret)
NT_STATUS := DllCall("bcrypt\BCryptCreateHash", "ptr",  ALG_HANDLE, "ptr*", HASH_HANDLE, "ptr",  pbHashObject := 0, "uint", cbHashObject := 0, "ptr",  &pbSecret, "uint", cbSecret, "uint", dwFlags := 0)
if (NT_STATUS != 0)
return False
cbInput := StrPutVar(String, pbInput)
DllCall("bcrypt\BCryptHashData", "ptr",  HASH_HANDLE, "ptr",  &pbInput, "uint", cbInput, "uint", 0)
VarSetCapacity(HASH_DATA, 16, 0)
NT_STATUS := DllCall("bcrypt\BCryptFinishHash", "ptr",  HASH_HANDLE, "ptr",  &HASH_DATA, "uint", 16, "uint", 0)
if (NT_STATUS != 0)
return False
if (HASH_HANDLE)
DllCall("bcrypt\BCryptDestroyHash", "ptr", HASH_HANDLE)
if (ALG_HANDLE)
DllCall("bcrypt\BCryptCloseAlgorithmProvider", "ptr", ALG_HANDLE, "uint", 0)
return CryptBinaryToString(HASH_DATA, 16, "HEXRAW")
}
GuiName() {
DllCall("bcrypt\BCryptOpenAlgorithmProvider", "ptr*", ALG_HANDLE, "ptr",  &pszAlgId:="MD5", "ptr",  0, "uint", 0x00000008)
Random, HMAC, 1000, 1000000
cbSecret := StrPutVar(HMAC, pbSecret)
NT_STATUS := DllCall("bcrypt\BCryptCreateHash", "ptr",  ALG_HANDLE, "ptr*", HASH_HANDLE, "ptr",  pbHashObject := 0, "uint", cbHashObject := 0, "ptr",  &pbSecret, "uint", cbSecret, "uint", dwFlags := 0)
if (NT_STATUS != 0)
return "Error"
Random, String, 1000, 1000000
cbInput := StrPutVar(String, pbInput)
DllCall("bcrypt\BCryptHashData", "ptr",  HASH_HANDLE, "ptr",  &pbInput, "uint", cbInput, "uint", 0)
DllCall("bcrypt\BCryptGetProperty", "ptr", ALG_HANDLE, "ptr", &pszProperty:="HashDigestLength", "uint*", HASH_LENGTH, "uint",  4, "uint*", pcbResult, "uint",  dwFlags := 0)
VarSetCapacity(HASH_DATA, HASH_LENGTH, 0)
NT_STATUS := DllCall("bcrypt\BCryptFinishHash", "ptr",  HASH_HANDLE, "ptr",  &HASH_DATA, "uint", HASH_LENGTH, "uint", 0)
if (NT_STATUS != 0)
return "Error"
if (HASH_HANDLE)
DllCall("bcrypt\BCryptDestroyHash", "ptr", HASH_HANDLE)
if (ALG_HANDLE)
DllCall("bcrypt\BCryptCloseAlgorithmProvider", "ptr", ALG_HANDLE, "uint", 0)
Random, Trim, 10, 28
return SubStr(CryptBinaryToString(HASH_DATA, HASH_LENGTH, "HEXRAW"), 1, Trim)
}
String() {
Random, String1, 10000000, 99999999
Random, String2, 10000000, 99999999
A_Args.JS.GetTime := String1 . String2
return A_Args.JS.GetTime
}
GetTime() {
static SYSTEMTIME, init := VarSetCapacity(SYSTEMTIME, 16, 0) && NumPut(16, SYSTEMTIME, "UShort")
DllCall("kernel32.dll\GetSystemTime", "Ptr", &SYSTEMTIME, "Ptr")
Return NumGet(SYSTEMTIME, 6, "UShort") "T" NumGet(SYSTEMTIME, 8, "UShort") ":" NumGet(SYSTEMTIME, 10, "UShort") ":" NumGet(SYSTEMTIME, 12, "UShort") "." NumGet(SYSTEMTIME, 14, "UShort") "Z"
}
IsValidEmail(emailstr){
static 	regex := "is)^(?:""(?:\\\\.|[^""])*""|[^@]+)@(?=[^()]*(?:\([^)]*\)[^()]*)*\z)(?![^ ]* (?=[^)]+(?:\(|\z)))(?:(?:[a-z\d() ]+(?:[a-z\d() -]*[()a-z\d])?\.)+[a-z\d]{2,6}|\[(?:(?:1?\d\d?|2[0-4]\d|25[0-4])\.){3}(?:1?\d\d?|2[0-4]\d|25[0-4])\]) *\z"
return RegExMatch(emailstr, regex) != 0
}
zCompress(Byref Compressed, Byref Data, DataLen, level = -1) {
nSize := DllCall("mCode\compressBound", "UInt", DataLen, "Cdecl")
VarSetCapacity(Compressed,nSize)
ErrorLevel := DllCall("mCode\compress2", "ptr", &Compressed, "UIntP", nSize, "ptr", &Data, "UInt", DataLen, "Int", level, "Cdecl")
Compressed := [Compressed]
return ErrorLevel ? 0 : nSize
}
zDecompress(Byref Decompressed, Byref Compressed, DataLen, OriginalSize = -1) {
OriginalSize := (OriginalSize > 0) ? OriginalSize : DataLen*10
VarSetCapacity(Decompressed,OriginalSize)
ErrorLevel := DllCall("mCode\uncompress", "Ptr", &Decompressed, "UIntP", OriginalSize, "Ptr", &Compressed, "UInt", DataLen)
return ErrorLevel
}
Base64Enc( ByRef Bin, nBytes, LineLength := 64, LeadingSpaces := 0 ) {
Local Rqd := 0, B64, B := "", N := 0 - LineLength + 1
DllCall( "Crypt32.dll\CryptBinaryToString", "Ptr",&Bin ,"UInt",nBytes, "UInt",0x1, "Ptr",0, "UIntP",Rqd )
VarSetCapacity( B64, Rqd * ( A_Isunicode ? 2 : 1 ), 0 )
DllCall( "Crypt32.dll\CryptBinaryToString", "Ptr",&Bin, "UInt",nBytes, "UInt",0x1, "Str",B64, "UIntP",Rqd )
If ( LineLength = 64 and ! LeadingSpaces )
Return B64
B64 := StrReplace( B64, "`r`n" )
Loop % Ceil( StrLen(B64) / LineLength )
B .= Format("{1:" LeadingSpaces "s}","" ) . SubStr( B64, N += LineLength, LineLength ) . "`n"
Return RTrim( B,"`n" )
}
Base64Dec( ByRef B64, ByRef Bin ) {
Local Rqd := 0, BLen := StrLen(B64)
DllCall( "Crypt32.dll\CryptStringToBinary", "Str",B64, "UInt",BLen, "UInt",0x1, "UInt",0, "UIntP",Rqd, "Int",0, "Int",0 )
VarSetCapacity( Bin, 128 ), VarSetCapacity( Bin, 0 ), VarSetCapacity( Bin, Rqd, 0 )
DllCall( "Crypt32.dll\CryptStringToBinary", "Str",B64, "UInt",BLen, "UInt",0x1, "Ptr",&Bin, "UIntP",Rqd, "Int",0, "Int",0 )
Return Rqd
}
LoadImages() {
A_Args.PNG := {}
Data.PNG := "iVBORw0KGgoAAAANSUhEUgAAA"
A_Args.PNG.LogoMH       := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.LogoTop      := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.Logo16x16    := Gdip_BitmapFromBase64(0,1,Data.PNG "BAAAAAQCAIAAACQkWg2AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAKWSURBVDhPRVJJT1NRGP1MNC5AEO3EUAql47OPvvm+oXN9bVGCQCkt5NlaeWWwEDGgCAEJjRAkRHDhEFlocGUkLo24YOPGnb/Ahf/E+1oST+7ifPee8w33XmAY+v1ix49ty7cNy89D017RzDAMWwcmtTbmL6meWpXTFuXEqzA0BRua/c9Xf1Xnl6rC8G2KCQawNJUSVFXgOJb0kf1OIsFRqky984j7PgEOH3SPjQiRAZ5CpChyWL1YVZwORyxKYU+90n+sNNGwO9tXGBNaTX0AzZN5Y1cQCIDLJptbTfI41DRlby9tFGTZh2YaPjzpKU0IftIPYIGL9rsFDqAdwEQGCayeuie/3ElnMkYpkgx+JCQoDjjHR3hbt9vj9ZptvQAtXr/P0eP2+LxrK7HaWiIeN+pgcCyTMRGA2eAtAaBLK7BVHWHDo/kQEm/Ahfb95zdl2Zgqn0WlkhyNGNwwDA1igzWlkvh4qozSqkD2+2Z0NDcTj0aM9CgkA3DahHRuyI7gxNecLhfmDWyuRmPxKDSjRqimDUN+TMTcMIRDnF6RtML5JebHxdrGoLVTuWrh9XKoVFbcpHjdKo9n6wYzO8lx50+LUbmvrC+rxaJ8ZzQOwODE9cUzSiw3KgwNu8G1dRwIBBvq2enQ9rNUpD6cpz/SZJIW5sJTegiFw82WsDaBdl64oL1co2ka/4JKJbS1mcQEI5ngW2wyXDF6wEhlwgByIYeWlj3QNv0KfzO8iydpHGPgu6e4WAAlG2G+kOz1p7LDaHW9D9wLOx1zhxTHoYjkZSSCoLBCENhcTsqOiok4M5AJzlfR7Ix4dkY/XusBiqZduyet+78uPf3eefTbsfQad9hIjKFXu46/dL45sn/6bD9466Dp4D8rxbw8afqHDwAAAABJRU5ErkJggg==")
A_Args.PNG.BarraTop     := Gdip_BitmapFromBase64(0,1,Data.PNG "AEAAAAZCAIAAAB/8tMoAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAZSURBVBhXYzA2NqYJtrWyYHB3tGEwMzYAAO2IDzPhkUQ0AAAAAElFTkSuQmCC")
A_Args.PNG.Discord      := Gdip_BitmapFromBase64(0,1,Data.PNG "E4AAAAYCAIAAADbH1ygAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAVzSURBVFhH5ZZ5U6NFEMb9MISEcAQIgZAQCHfkCBAgHIGEK5wBQjhkVw6BBcFjtWq9j9KyPMt13XV11fIoj1W8b6tcP42/pF/G15Cs4D9uap/qgu6emTfzzHT39B1Ztw1uP6pGU25H8IHQwqWh2OWhhTf/RWKXQ9FLbYF7DdlGWZ4R0Kj6w0/FDv48rfhCD8nyjIBGdW7npyQaJ5Gp9euyPCOgUZ3Z/DqJxkkkvPqBLM8IaFSnNr5MonESGVt5T5ZnBFJTnbnnm57xpwciLw8vXe2bfG5k6e1A5KXeiWfx66cpqtQno8mcbczJNpqzs03iTMCg/dehoMiZW2DTDB0KiirMecWaoYPFWplvsWtGHCm+KTAYsuMbiG8jLpr3CCmojiy9U2ityjFbTOYCGQXoeApLqkeXr6mZimqzf2N685CPTG9+xd/BudfKq7rxs/vwmY8QZ00/ZmXDsFrO2YkTVDWOin9+9xcONDe/RPyezjMTZz/Bv7B/IxR9Q+ZzlDwBfHMcOfsxSvfoY7LEVRc62sYhApE6bzTxpThSUJVdpoOzuk/NVFQ7hy8opxLOxWjKE91e1cWNiR7d+10UfpS1jupeMfXCtTd1ryU5kVJnK5eX5EQm1z7jU1BN8iNcQ2KPx6hyLeK5CSJb38pkRbVt4ACTguzpXPUG9uZ3f8NsH7yPIZlZaHXXtsyizG7/IEvq22L5hQ6DwcAv4ueKyt3+2pYZSl1H6DzHtLD/B/7h2BVHdY/bMx7Z/h6TnGLt9MYhejB6sdG3QqKhI0Ul1UW2WtG9/btN/vWJuz9Fnzv3s/xiMtWukQvi4W4HZ1/lyNEJMGKypLxJhrrHHpfJiqp4+qdfEDM4/zomV61uFapEL8r87q8tPVu28maZSTTiwd/atyMeAbcqCyvrh8QjL39w/iI6Z6ofiu7FT7aidqC4tF5WiR+26NQXMZOpcvbi6Zt6HjMw8yI6lNB9Qw/LUJ13XiYrqg53D6YEJBiIvILJ5dCEycwyVzt1QnQRGNY0TzNZ3rn2wftlrYAkl2kyB/jHnsAkw9Gn1r8Qvd4bbQvsxw5uYNoczaacfIk4SV2OD13tKplqWUU7JodNZYKb3CSZ5gud56SlutorO2WyogqIPcqAlEc2wShLFFX3neP48y3lHcEHI1vfiROxOVsJURTazMRnNCiqbk9YPF0jj2DqqeqFYJa95VnKxu56X6Km2b/JUFqqhAEmQV/q9MqQgr3SB38UCUVET1UPiYLu0UdVANc0TWljCZS5OuQqWnq3aadR6MBlyFrWwF+uRRbWtc6JX46PyegSwIpwePVDmZMEqSAkuZgpypKrPoSHYkBZI4zZMUmILpWZUfW6KqokM0lOLHUlJssoqcKQ6BwTF8V9zu78yO4R8XOgpB8KG4J2z8Qz6KMr71rtHmai81utfeeIL5nPI883eUjQ2Ul10yQKM9ktfpujhd3CkOacF0i6XUI6vsXjVEWGF6/KKeqFvKWX0HsUVYqW3o/AindYPTBsgnRVoyKkNGs5wSQ/ZcacZyUQkvxIIqy0x4Zqz/LJtc/FJBxcdUHR9YIzscc0VE8oimpD+yJXQdbRXfGXhMwrKMXPzqSFkFOnB/CHn6RbGF58i7tSfQ9+ijZPCLFDJJPh4ufSiNh4V7B+nWApsXtwUt6GYlf4ZmPHMiZVF5NegmwnRviyyMjyNboRu8uX+FIcGlV5tU4r6XI1FdJ2cwpSV44DbnR8mhFH6k/Fm8E0XxAc3eqxmpZSOBF9/TwN1f8fGlUCmj5TcbiJ0NOowkPQyvKMgEYVWIpd5AyPTUVNIJ3wzMhkqUMkjJgZgb+pnhbS/f0zi25p/HeqgC6SF0UzbnFkZf0F9sdYKfywHLkAAAAASUVORK5CYII=")
A_Args.PNG.HDiscord     := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.XClose       := Gdip_BitmapFromBase64(0,1,Data.PNG "BwAAAAWCAIAAABc9GulAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAABvSURBVEhLYzCmARg1lPqA7oZ29fTZ2jtBOUgAKAiUgnKwAXyGAjUvW7EazVysgmiAgPfRjCDGRCAgHKZwg4g0EQiIiiiIcUSaCAQDZCjERCAJZ0AlcAO6RxRWI4gxF5+hNEn8ZINRQ6kPaGCosTEAeNmPBGY4+RgAAAAASUVORK5CYII=")
A_Args.PNG.HXClose      := Gdip_BitmapFromBase64(0,1,Data.PNG "BwAAAAWCAIAAABc9GulAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAB1SURBVEhL7dJBCoAgFIThbvfu4kG9i7ugXRA0IEiMokOmbYQfiWd9ULbtZp+3UB71Nx09vT+coyHCEFs0fFZD8fAVArnFIdV4fSIUEbW/aYJEEUkHFTlRRD+hUcSaLuiGvOkHVSQUt4YO+flft1Ae9TcANbsB3Xa5ri4MuhIAAAAASUVORK5CYII=")
A_Args.PNG.HideHOFF     := Gdip_BitmapFromBase64(0,0,Data.PNG "BIAAAASCAIAAADZrBkAAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAACASURBVDhP1ZNJDoAgEAT9k7+Zsz+ABOTz2tqjGZZE8KR1kJ6lQjg4icgyCJSJx9wNrzk0bXTzBW1Nabvw3mvX0NC4rUVVklLDRggBAV9k59ydz7mSaXaGTLTOp43bGPAk5BgjS+uAUgPFBqg7DQ1gz6JdQ1t75E/amx+HxxAisgNEcCwtspiqeAAAAABJRU5ErkJggg==")
A_Args.PNG.HideHON      := Gdip_BitmapFromBase64(0,0,Data.PNG "BIAAAASCAIAAADZrBkAAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAB/SURBVDhP1ZNLDoAgDES9k7fp2htAAnJ5HZ1iGqwG3RjfQqafF8LCQUSmh0AZeIzd8JpN00Y3/9bmUpZKjFG7FV/jthanEjgaNlJKCPgihxCOvM83Ws3OkInWZurfxoAnIeecWVrf0YDdIE3H1wD2LNqtXGr3fKK9+XF4PEJEVku1LC3F/kcuAAAAAElFTkSuQmCC")
A_Args.PNG.HideOFF      := Gdip_BitmapFromBase64(0,0,Data.PNG "BIAAAASCAYAAABWzo5XAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAB+SURBVDhP7ZDRCcAgDAU7SZZwA8fw2w0UtC5veYGAtVEpfrYPDpMYDvHw3tddrLWVRcaYLYjok6KzlNomxqjugaFIspoJqghJKXGNEwkh3Pp2HzxE/VKbft72wxdJjX9Bcs7qvTD9o342mw9FQIu2B6aiN/yiNSxyznGxB9ULmnJSBvMOU+EAAAAASUVORK5CYII=")
A_Args.PNG.HideON       := Gdip_BitmapFromBase64(0,0,Data.PNG "BIAAAASCAYAAABWzo5XAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAB6SURBVDhP7ZDRCcAgDEQ7iUu4gWP4nQ0UtC6fcoKgkhrBv9KDwzMeD8lljOFTO+e4gqy1RyaiH6RYBd2lcK8Yo9hbgpq0GfwKglJKNeOEQgjDve+LoLnUa563vPxRy9gLlHMW32F1R7vzJQiWJPVU0K6/DvLe13Bm4gdnllIGZFPrlAAAAABJRU5ErkJggg==")
A_Args.PNG.CTA          := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.HCTA         := Gdip_BitmapFromBase64(0,1,Data.PNG "EoAAABGCAIAAADkcJVdAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAABeiSURBVGhD7VoHVFRX+v+YgRkYYJg+FKlKR2wUuwQVUAEVC7aIDRHE3hU3FrKxpEisMca41hj9q7Fr4qqraIyJuomKClawYEAEC0Xk/n9v3tvZycSCCXtONmfv+c747nfvu+/7ff09pKhuiX9i4uBNypjzp6R/w+Ox/pnof/D+m+mPBS86rmfPpmFvu3okyx1SJJLhNrKBrh4xsT3MttWe3gxeTFyPrm0iezUO6esX2Nc3oEez5jGxCWZ7fjPh5FQb2XCi3kTdiXoaaARRir08umtvs821pNrC6968zSAnlxESSTJRElE/A+F6pFQa276T2ebfQPFtO4wh6ks0kOjDyMidGRnZq1Z9NX36YAPCXo2ame2vJdUCXtfeSfXc04n6GJQ6jGiyRjM3ICAzMBCaHkIElRs3Q80xXbp36tzt1/ru0rFLQlirrq0jjRy4YvcWbbu1bNc5Oi5Vag1sYx0d806eZCbjsz598NChClViQPAQjTbZXj5I79SzSRh/Am6HH/X38oZDdYmKNZ5spNfDG6ZSA1I80TsNGx5avPj2hQvPKiv5Z/9zxw7IBO0O1jkO1jsNkyuGW9ukiMUpIhEuwEwMahQd3wsAhilVKQbLDMV+G1n38NZgAhKMM4gozcICq3CHe+fP8ycbx85p0+KIoNy3iRIM+oWWR8GDXFxT7OxxGqa9DCdjTz/fADPhXwOvf31feCBiYNvMmcIDfzmWtm8PhHBXPBiUSDTAQLjgTZ1mbQOvgxCQYIpGk25hgc2jicDsj1+JZIJcjvOBYXG7dsKhjNU8f5579Oiu996boNHgEBw41c1t4/Dhe2fPXhIVBZcZaQiNdCurBaGhWZGRU7RaqAmwE8Jbmcr/KngIKqikK9Ge2bOFx/5qrElM7AjDentvnzr1m48++mHz5pyDBy8fOvT9pk3rU1LwSEiG3wUREZcPH4bZi2/cyAwJgaGADRcPb98uLyvLXrMGlvm0a1fhUMauHDnSyeAysA82L4mPf/78Ob9UXloKJpQ1zMLi+unTPLPq6dP5rVpBiW+7eZhCeBW8fg18cfRMDw/+COOoLi8vKigounHj6rFjY+ztAe/kmjXC2i9H7rFjg8TiLkQ3TpwQWIxtGzsWtoLo3372mcBibKZON14mEyaMld69myaV8n6IzUcWLRIWGLufl4dw4CwvEj2rqBC4jG1OTcVOFBJTCK+CN1SphhD7fmm6r999N0WrRajgGTAL/ARP+uf27Viqqanh95iOvRkZ7YmuHD4szBlbP3Qo/LYH0d9NhH6/RYsORHcvXBDmjJ3ftQvi4kEw7FfTpglcxu5dugQmnCJdJCrJzxe4jK3q2RNnDvCobwrhpfCQ1lIsLRG1Z7ZsEQ5grODcOUgGJuIBhMyJJyGWrmZnYxXwrp04sS4j48D77z8pKeHR5v3jH92Ico8cMRzADR4ehD44b57AQgzHxLRA+EVECHPDWNO7NywPobdPmiSwGLv94484MMYQ3sXXrwtcxpZ17gzBkEVNUbwUHvI47wOXvvlGOICxo0uW4GgEJCKbJ4AEwvu5ufyGVb16ORBFEOWfPctzftiwgXPOU6f4KcbagQMBD+eYhvTy2Fgw4SwXd+8WWIw9f/Ys3c7uLaKt48cLLMaguE+6d58SFrY8Lq7y8WOBy1hWRAT6gX4N/ExRvBQe8grgIR1D/cIBjP1j2TJkGlN48M8JdnZPS0uxCnPlnzu3d8WKS4cOGTPBX/z8IDdUzk8x/ta/P0yHc0xt8mlCAvInDDJOqayuqhK4jJ1cuTKM6IvUVGH+8jE/NBS39/UNNEXxUnidOndPtbDADef37BEOMPg9NAThYDHk5VQD/r94evKrv469z3r3jjJE6b2cHIEFeAMG4ARY78v0dIHF2Oq+fcFEIoHXbR07VuAaBgrPivh4YfLyMcffHztR/U1RvBQeCH0tvOXrBQuEAwwje/nyNCcnGA2Bh1/gR+XhlwCvpKDg0oED/BRjto8P8ju0cP/KFYEFJImJvPXWJSUJLHhsUhKY8As+XT24dUtYYGy6Wm18BAay5fdffJG9ZUvxzZsCC49mLMPNDfmmd8MmphBeBW+AZwNIn+nvL5zxr1FTWVlw+XLhlSu7MjIQGIujooQFxraMGRNJ9PPVq/z0zNatsAasV3TtGs/BgB+GEjUn2picLLAYwzVSCJwi1qAy4wkY85s0QQMoTOBBOTnYidvnh4QILMYqnzyZrFIhyfVsEmoK4VXw4iKi0gxqPrNhg3DMLweKKXI3xBXmjB2cPx8PhnaFOXTv6AhxH//8MzeB99bUFF66tOuDDw4tW/aosJDjGMaW0aORgSDfzPDwM5s380x+ZGi1aHGFCWN3zp9HPkM8G4MCo6ywEA0QWrweoS1MIbwKHmiIzhHRhdJ856efhJN+OeBLc4ODhQlj323Y0Ixo54wZuOYFv3nqFOQuunSJmxjgGdj/Gv+a7pwyBe3BP03inB/lJSWd4SDt2wtzg/UQ9kgB8EaBxVjR9esIAXQzaLJN5X8NPLzOjbK0RPeQLJEcWrq0yqRLwDj5+RpoEfg3Dk/bl/nuxpSUDE9PWHuuiS8dW7kS8GaFhFQ8fCiwXjQyw8MRcsLEZLzXujW6gndMDrx7/jzKFbLINI1GYKFaFBXBdEgHeGk0lf818EBxb0UBIXo8ePwknT4zJHZp/MjVSdM+SRwDFQIMAjqaqB0RYEB/aJfRym0dP/mHTV/A5eCZiD1sm+ji8uNXXz0sKLife/3m9xdzDp36fuvXh5dv3jZj0XSPFkiwuNdYPzGuZGfPDQvDjUin0ODCNm1w+3fr1wMqXIZrKiwtrxnenpDPNo0ZA8wIpU4xXU2Ffz08UOeY+KFqLW5GWzDPgz6Po43x9H+JdGKWS85S/0ufBubuaHz8Hd9kkQgionwBHqAi6+IC2QJaACHl4He0WDyMLOBIo0Q0TkoTbWmyLc3ypulKKRxhrofHZ32HZDbuki5rAMBwy4mG6oobWxMhjaGcQNFpUmtgBkKcM9PdHdqHErFtsKOzmeS1ggdCswO5s8LV7Hkkq2rBHoYbKIw9CGVFIay4KWNv7R7m3oUsVsY4XtwUfHVnszletvBqvPutiXU6+r7/jmSP4ZacoN+963b/eODjo0HVZxqzK6Esvzmrblv+bfNJGhvggaDvBdDuUbKDU90nq61hN6hscUvtnskNNiQ6p4gsgAqv13DCNIkU1/AdeDXeGJPqueHd0kzs2sJLcqqHurQqQscKQtjxBtXHfSuP+lUe9a884led7ce+9WGPQ/Ylu6aKJaw4glU1YyxifbwzurNpOhm73Zax5ox1+CRCh0NqTjdjDxqzC0HspwB23p+jG/6ssNVcZztY+PR8JMn27Ek4Yx1PzvJFolrZ0RH3suoWjEWenufPebtYDJFiYnvg7S4xqHFCWCv4l6m0RqotvJ5NwxG76VKrit1N2KUmLDuocp/3k50Nnu5uUHXA79n+oJpTYe+4yCbZSthZrHqzy80+aavBS8AMnazySDA75c2uNVvWSgV7PtwRyL7zKz/gw44HsuONqv7eqOps6Mlp3pAbpri+OoDdCK466seuNLy9KQhdwcmZ9VlRs6rDPiw3sGh7cDJxBoyLjDGT8IVUW3hQFVoKuMFcV9sFYaqloaqH67wrt7o9P+y3p7/zCJ1susIGjpfpYff8YNCzvR7sh0YfNVEFwG1EkvJdQexrT/Zt8MIAOSpb6Wa/mv2e7FTA3sGuiVaSoSRGGoRVob5UEuWv9GMnfJ/ualB9oH75nqCpDvKLC+qzbB9w2BHv4s2BYyVW2NmtZTteMLzZgIxymlFt4YF6Ng1DQCNbIEKg5vyFXtXrnNken89aqhD0CBJIOcfVrvwLv6fr65Vv9syZ4755oEv2KNfHG7yerHVhu/wy3WxTSFT2N++KDfUqtnl9P6He4naqz9sq10drPvCX48zRYqv7n/pUb/N4stG9crPr401e5zLqF670qtiEQ9wqv3R7vMkvQyfDTgjDS4XOsVfjEKOQZvQG8EB4jUhycYXyxtlIC+a6PflIw9a4bY7SIOsgcQHhTJ2sdLlX2RL93fd07Mt67FADts2tcKGuZJG+crXXDI31aEvLsuWepR/r776rq1njDIOwY77sanDF2mAcMs5G8mBZ/fJVTvc+cLmz0K10mXP1BrfS5c4li+s9WFKvdJm+Ym2Dv3raca1zYCPI09cvEM8dqlCZCmlKbwBviFrbvXmbTp26At5EO+mtqc4lGfLnHzpuj1bDLfEYpOwZapv7ma4lc5XFczWXxzt+m+acn+FUPEddNFtZutB1gkwyyV7y6APXolmK4rnqm9P0xwbrD/XR/r2ffmkjB/jnLCfZww/cyj9UnUvTfxnt9HSRc+FsVUWW7sQQ55NDnSqz1FXL3D/ylyNK0TrHdOmOh/KUEN7aTFqe3gBeqqUlDkqxkaGqTrKX3hylu59uUzlTuTuaSxioioiraQrr2xMdi8bLKt/Vf+QjDyOLxQEOT+fofx5nc3+q40iR5UyNddksx7tjbGveU+/qpG1l+JSSQBbABustrG9flulcOt32x2TNPC/V3Sn6wgmy5wv0q8PUOzqqqjIVlfOcVjR24N/KEXJ454ZDIQ7xG921d+foODOZXwMPCbdHs3BcxEbGAFuqpVWqlYSD4WB9a6jyzgDLJ+m2+9sr4C2AB9hT5dY3h6vvDRY/mqDK8rZDYZjjKCseq7k/1PJWinoYiTOdbEonqPIHSe8kyy4PdDjSXX2yp/r8QHVOsnOa1CrTyfrRFHVRqiRnsDpNbHO6t6p0lLRssmauk/32tvLH42UV09VrQhygiEG/quDJ9g4DPLzMmK+CFxcZbcBjZbiOQTRDYT1CWgDeZAfr4uGaBz2IpVmfjNXAWwAP9XeUteT2EN2zQcTGKZf4OKBLznSSFQ+RY+ftJOXbJMrytKtMl+fFU25XcX5vcdkQSclgq8I+xGYoPnS1y9TL2CTl/V50qY8ikURfhslZuuRaf3mKhfW+dvYlA8UVaTbbWnLwhqg1kKpLVCwXL527IcFA+4P0TkbheXopvB4hzXm3HiG1jjL5ot6tVQRaoSEi0dpG8lt9lGdjlfPdbWE37OQNuMjLLqeH6utIZYqNBF40WS693k/7eJD8m0gVtDBWLr3RT/1siE3ZAGlpf2uOBlhXDLK5m6QZZy9JsrI82VnNRjv8mMB9pPurow2b4XQ8ShFNFoc6qNgYu5p05erGCoT6MIUSwiSEtuQl5EUdaWFhlJOnF8Pr6xsg3GAguLhxCVCHKVXoklEhxlhLB5EIvSzaaFRFEK7RecSTGLGEbhMclOCp9tJMnW0/4j5toLEcIpVsauqwsaHtuiC7tYF2nwfYbgyWT1RYAw/MEodw9XGYpZLCF0aQxYee8qn2Ehw7UyndGq742NMu2UIE/fbz5j4Zve3mwUvY1zewn7d/mkhk+jcM0IvhoaPrE9AQGuJvTghrCaaxo8PFQDdP3hu5jy4OCqRmbENGzZTQVgfaakNH7KnMnb6043pImBRvG2OJsjV0VkHvG14gwIERYF4Q+m+cc9COzmtphTXXN6OyjTF0zNjD1SHDIVANchiYyQolX8r5bAdCwoMN4KVm2eXF8IwEnAhi/gNGfLuOuI7pIvxBj/+LT3zbDrhG48fVdCk986AiFVW6UoU7Farosp5GiLiPTjDLKilV6YjVpzIXDirvzzxB7rW2xHzpkZ5uq2maFZeE+/oEIM4HuHv18QtCpPRr4DvQ1T3JyaV3cFNegJ5NQo0nAKfZB1yeXgOPJ95uXdu0x0Ep1jYIP9NVUIrMFgA2yqjcma7r6ZaObuoo35Hu6ukvIs5jYYR1tvTEhW7rKVdLk8ScTYzC4d71tvTIie7o6aqOJoq4VbNS1qlTN2jTlJMYGPy2mycSHqqCKd+UagWPJ+jSKBDONfoqrMp/rj7pQAVqKvOkmxq6oqISTyrV0yoJ536At0XOme66in5S0wRLrn01nobVzfZUqKaSenTdmYtYuL3ZVxM+1aG16Nr6LVP+q+kN4PXz8eelgYv2ahRihIcoRzs2hehBPXrsSZflNMeKPrelGw5U5UHnnDjrIWY2yShfQZVedEnPfTWAx/KngTjwdsR86Jaasu1otIhLSGY+gtpt3M93ZKb0sq76DeD1r++DTPXrP7um2NohT6y2ozJ4l5aLtxaGBPDYlQq0dE1L0yy55LFDThWuVKijU0rO1EDIy4oUhbjdKadiPZU401kthxyrZq88eLXjNovF6DONmbxzVGyvRs1Q7owZwYzeAB5vrtj2MZ06d0e/xzPh95APxsnW0kNHuqykO660zo4Tt9SdLquoSEef2HLfEfYpiHnSHTUddeCMg9JihIcag9V7ak4jZ/Rc1uESsr18mIMC3gg8eFC3Fm3xSm2WGHs0E4qzKdOU3gAeCErij4Nz8pw+/g2RBiaI6IwdFblQMbwRbuZG1R50WkaFrhykjRLCW+lee845EX7HtYRuBg6JmgGzAxust8+ec86ftbRNynWhfNmA1vhudpCji1EGMwJCZFTTxsOU3gweaLDeCUXG6OuojZBjqZQq3SlPSznIKK50T0f39fTAlXLU3PWPei43HnDg9tzQ0E8a2qCgxWKuGOxU0jwRt3pYRfe19LMzXdTRIhFtkNMGO/rcipbJaLgFhzDurWijDC+guoLXKaarMamg4eYaCKIjCnruTrkauqelIxoaJaY5YrrlQvkauqqhYleaJKJdcg7eBRVXNp65U7GOHjlTjRs91NNkEe12oEIt3XCkQmd6oKNyV3rsQo8cuRI6x5JLTkhsRhlqT28Mz5RiYhNSRSJY7ysFPdVyAjFveseC870oVGorYl50z5Ur9J/K6P/s6ImGy5yFjpSDNFOf8nWUp6BqLxoHeHBpP7qh4ipHtTddUdA1NXeBWM0wvCijuJs9vTb0u+CB4PeIvTEiOqWhixo6IKfRFlzqg0nnSOiWlkod6YkbzbCk6ZZ0UU/nVJSjpQIXLuvc0lOVGxd1CLZ5EjqjpBwd5erpgpIKnKnAkTPjN0rOdPCR1zjnS+j3wuvSoTP6aWRCpDv8QhTk9FGGZhog0Xx9aEWzJFwXgg34RcIca0FTLWk8Xu3FNFfCcUBY5b61WNB4EdegQx0ZljTNkMZw4AhrG7Pn1pJ+LzwQ2gs0ZRAR2Zzrd+3lKMH9fLh3DuBB6oPcQIv3YC7dGzoSHioaSyxxBdDSCr0eToCC0M1gA5ZAA/nqL7aMb8d1tr+B6gAeCEGI5huo4iKijHUfTWMf/yB0uugH8NKJPIRGBHkchRgteJ+AYIQTahr6dZRpFFLc/oLV4KaxHTobH/SmVDfw/rD0P3j/zfSfghcZm9AmKrZlZExo68hXEDbwhM0g3GV2zu+k/wg8SAmJNS6xS4z/AeDqig6OrqMOCjPjyFse2zi8Ncc/OAEXuKtuEdY9PB6bOnpFHmMHRut9GzYJahqO6ZKxrrjAVKEZs5/lfRypbOAfxE07Ls/LO7A/L29xRz0QwoZmB/4eqnt4kA92+ziP7R8pd3H3BAagMhKmtopR+1huVmuZzskFG9otzsvNatsqKzc3qx1W4bF1aMC6hwfTwSC5bH+KpUSl1bvX9zGFh6lENnIvy13UkmxkthJJW+DCNbVchH/b2iuwpw4NWPfwoH779kthi5Zisc6pXlAzTlwjYQrrGeCJ5Q5KSWug+xjoeHxZbe1hQCjI7MzfTHUPr0nzNraRS3LZ3hSxGL6HqfmqAI+sJBIDptYcOgM+tm8EbkEE1pV//mesp+yYZcD3SusB0fC9QgY1jr0jZPbIN9hpduxvo7qHB9eCfJLU/RB2X6o9H3vInEvHeQA5lv4ND+hyF7WylMBLlRqdIQ65W+rQP+seHhQP7wIqWbvF//5POFdXdHTh4AEqCsM+lofYSwG6rNbIn9gMSPhti4R7YBRU8MeFx9c9wIDEIMiKaxAwAx5+cQ0kMBeIx8bvwS+PE9d/XHggHiGPxEg8PJ4wNYIHH5thc/4WftsfN/Z4AkJeYiMkHgNPRj7P5PMkfwtPPOf30y/g/SlJgPenpW6J/w+hwvmYUYM3HQAAAABJRU5ErkJggg==")
A_Args.PNG.Tibia        := Gdip_BitmapFromBase64(0,1,Data.PNG "EoAAABGCAYAAABrEgIKAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAsASURBVHhe7ZsxiBvZGccXDLYwLAiMbdlgGHAwyGCwMIFoOXLscQmHSBFESKFShS/R+QhBR5otVarxXRSSI0oqlSqFzyZZSKNSpSrfKZ1KlWpf/r9v5hvPylqvT1rtypuV+d/MvHnz5n2/+X/vvZnldn76s71wqZNloD795WeXeoeOgHry5MnGtbOz85aW1dsmnSkoh9KsVcJ4UA2taikMu6XQa5W3HtqZgHIAQAnTeqyx9ieVEEJb6oQwPwjz8b7V2UZYGwdF0M39kkEIoSH14m0KaSAJFGVzlUmzUeywZe2dlzYKimBJLwLHMTEkwZkKyKyWAEpAzaoS5WwFdVDYKlgbBzUbKsVwikEBiABNVWagcFTiMIOUgOK8QHWr2wNrY6AIsNtMIKVuEihSjvHJyjLwDJKcBKRxwUBNWvmLC4rAUL1SCdOhgrdxyZ2TpB1yUGw97RzSKArzXiHMOm9Aebt+fNY6NVAeRLNeD9Vy2ab8o+mFc5K0SlMPR+m8OUrnJgJ0GIVZu2iQgIUraXc6nYbJZBIOWq30XsdpWf/W1amAonM4iCC63Y6tkWIY2mbTDiBW7o5ySDom7QTKIB3sh1krdtSg3Uwh0bbdo9cL/UHfNDg8NLHP+UajsRFYa4OiU+2Dg3A4HIbRaBxGw8MwH7WlZgzBICEfsCljKUDKad/SrGhOMlACNKlpphSwQb1oAADV7sSQOOY+lM1mM7UV/9gfj0d23l23rL+rai1QdIZUO9QTpZM8/Um/E6YDuYdFpaVdnHKeUvNBOV4uTOJxCUizRilMG9oq1Ui30JKjVLfb2DcotF9vNs1JPBDcBRjXPPkHPNzlzjtNWGuD4gmi2WyqVXUrzKYJJEupmpYHRZu9AAGA0NGCUqnF8fRAcASEMs7N5SDK5s1yaJRy9hAARdB1pRQQgLYIykV5r98zNeXyrQJFIHF60Hk9UbkqzLqmSbcRRnWtyuUYg9FXyg2UcqgnmAmg0JG7egILLNXFYZHaZtwDTk3AAAUkU+KqiRzEfXEzZZ52gOLarQJFB7E6YxMdJgBgmXrdMG4LQBbQYVatWJRTB2CCNZWjymqb2ZN021fQ1VrNQADKB3BEGWA83YDKNY2oEAb505sF1waVzkTaeueB5+qrHFjzvl56pRhWDMfKuvUwbVVNBkouc1D7xaK1DSjEgA4ETy8HRDmpBqRKtWbXNARpGukVqpA7FVhrg7Knrs7SSTqI6LjPUgSGG3gxJg0HVY1BvdhhwPGyWSdxnmAxfgGqnM/bIA6kku5D+gEkK87TPnWKpZIds0So63pAjYs7grb+Cn8tUIgOsDwASiVJEaD50/VtQZ3t1zUGyUEOylylfTtWKtpWoABnoCTadAjurKwAyDkXD82cCCi5ai5Qo9z6i9G1QSE6wAxlQKIoROqoi84TLOUEEKdekoIuPzZHVWx8MUhSmeuS62kLMItwEOd5KHwU5FpAAQhXTbVlvOprJl0V1qmBIgWzKZCF5WV51eOzi7uK1GPfgVmZD+QSwQLLwTisZeLeuJp05XpSry+NBWisLaCGldW/RpwKKEQHmNJxDYF5WniQACP9CKJZ0NM+YLGptPNUlKsoqykgILUlAh2Wc3YMJJc71cU9zLVqnz4A10HThrUlN5HS5w4K0QmeJB1kW8nlrOM4yYOgfLSfCx1tO8VcaJUiE+nmATqkgcQrDW5wd3l7Lu6Zbd9TlvsgBwZwFrqMk6vAOlVQiE4wJWN3YNBpOk8QCAjTRt5SYqh9YFCPcoMnOSTqTGpqS1tEGfUA4G0CiS0PxdIucS33dWB9OZi0I71ZBG8FKERHxpHe/BVcRwIcrqkUChboUB2fHei1hoEWCJRlZIOwYAKJujbNqx7nPJWysNiybkpBSaQwKY5r0yVJkt5bBQowDMysk2wxqafJ1wBSgYBZ3wDDvzu57POKIAIonbUkrsFRx4FqAUpb2nd38WD4EmEL2eQtYGtSz0Vn+k2tyEdte6/jSXonGTNwiDlFwIDiYNxV6Xlts5BITa4HiKcebsqCclgOCkfZDKuHtQoktDFQiE6xIkfseyfZslomcEAYFEEiBV0ODECLkLJuIr0YgyjzMclhkX7A8nv7/VfRRkGh4zpIGUEwhjkIlw/qiDRDAHJIAOAzzGFNg31F9QCyUAdQQMRZ6wBybRzUu0QAg6bSoxf/aZ0/krr4uHfkeFgyTfus7jWDtTXdV49CcrDsXzhQOMNg8XGvpRREzQV5uUQ9nMRsxtgEEMC4Gx0UrgIUgzr3WRfWuYJCBEBQ2QBdPtZk5eeoyzXAIXV9PHNXUQeQDPa5XDHkC6vNdq6tAZUdvN0dy8T5rLgmO/gDCoiIsczclI/CTkHvmtHqXz3PHRSi80AgYGY/k5YG89KCWHuxrhKAZbMk4BwUacesuLOj1EtA7USru2prQLmrDJZAAGUZqBTWElDAJu1YU6VuAlBGhVJtJVhbAQrReQK0dZX2U2fp2MC4OM5AAhALVfveJBcxyAPJXpjdRQ5Kzlo1/bYGFCIAZkE+ibh46+drA1vfR37evkDoXZKBm6VAmm4ClCs3Y1CJGNRzeQH70EEhgkD25BM3EFxBboiVD/lcoqRurMxYVKqHXKUdq1iN2+GcBKwLAcpFMIVqN0S1vm0JGgAOzwIHTiJzC1CAJCc5qCOQzE1+zY+DtdWgisVKiPYbqVJ3SAQduyMOGofhOD9vcqBZsABbwVVbCwoRDJ95ScNCxB8uYrF4POqOOBWp74Ctnq5DDtRcl4G77J7HaatBIQ8+KghYAiir1CmZwNP6Doq6KSDXBQOFCAqX5PP7qY4GH8NcvCa3U36jI6Dern+SPhhQUb5mKkdN2+ZzcooAHOcQv6ZYqB+pf2FTD3nQ1XI7NCrdo7COCZxj6qPlcC8oKJzhoNjPOiSGdTwor+9aVv8kfTigmMlymvWkNOATQFHXnbR4zYUEhQiMWW9xMD8OVHrN4gSQTgIXFBQiuOO0rD5aVhctq/sufVCgzlOXoN5Tl6DeU5eg3lOXoN5TZwLq8ePH4dGjR+Hhw4fhwYMHJ4p61Oe6xesXz52VzgzUwX/sf1l56zc5PAz/1b+///onIYq+Cv8Kk/DtryIDBhC//tFv/2n1/vGbCw6K4O7fvx/u3PljeBW+D51Pb4S7d+8KTgyFrZ/7yy9u2jHuyV7/f+EogiP4Gze+DC/D6/D1z69rtZwPt27dCvfu3VP5jbC7+0X4LjnHMeWAASSQuR6x7ym6LFU3oTMFReDAeCEYz/d2wrVr1+wYF3390VWtmJ/G554+13+T1PxbxZx38+YfUrfRzp8Okwr8/v2VwQPYpmCdCSgXweCoGNSVcP06rnomAD9kQOn3+nn46OrVsPvxNzrzg6VpXC8GBThgxU780sr/+tkda58Hsuze6+pcQeGo69d/r1T83hyWOkr7V67E5794GcJ3v7uq48/tHGm5u7sb8s9emZni3+vw50/yaaouu/e6OldQwHAAi6Dil9e98Fw5+OLpwrk9UvNF+FzXx3UEUI68ffu2jVnL7r2uthAUmacOASoB8tSgZUA9VS2l515aJ26PCYB7LLv3ujpTUDxtlgCk2jcf71oKMZgvpt7Llz6Uh/DqWT5c1Xj1BihwY6fZ7/WL8EKOoj3GrgvhKMYPpneWBIuKocXCGS7OsYxwZetlRb3s2uu0daagmJF44r4eygo3uHxGQ5zLHmfrZUU92r4Qs56vp3jqiyLIZfox9Wj7zNZRlzpeKahLnaS98D9FGyHP6ot95AAAAABJRU5ErkJggg==")
A_Args.PNG.HTibia       := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.Bombcrypto   := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.HBombcrypto  := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.Rots         := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.HRots        := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.Lunarush     := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.HLunarush    := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.HSpacecrypto := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.Spacecrypto  := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.Sunflower    := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.HSunflower   := Gdip_BitmapFromBase64(0,1,Data.PNG "EoAAABGCAYAAABrEgIKAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAnbSURBVHhe7ZpZcFTHFYbznCAQi5HQvo5WJLTMSCNpJLRLaEOWwcYxiwGRItE+WhjAgKmigl8SO3ZRqaRiNrtSTqrikFTZ5QdbwsGQp0hiyaOFIW9+kPyStYqT/s+dnmkNPZoLWhH3Vn11u293n+7z33P6tpbvVTV3kEVoWKgBz2mLOZglVN3Oly00rCihvtiRGxRd/6XEEsokllAmWRahdEIA+ndrUND++Y4cX19Z1tlfDFaUUI/+0xoUXX8Ae7Vtu2fdA8sLgRVRJllSoaST9HU8PfLyz+Ek+pcAd10kSdBHgvESaROsmoiyhJoD1RHVQZVHX8fx/X+/S/BB3zoYWUcfQ1zc9WWepzFHu475sqRCySgyxPEj66pQj761M7IuRZ0LOQ/mfaYjKlCYwLollBfsQwBOSZFUcdzlzqCo/VRx1L1r1QglHcJ+Ih1VBdAJJFH7YZyMRNiTHwQ5jxRpIcWyIsokiyKUKg4Oi/i8yztQndaJEgp1PMF2AOr8uvU9DZZQJrGEMsmyCIWDpPz864QIhTyMMl5xLKE0PDdCqamjEyIU6nhLqDlQxz/TQqmoi5bnHevAqUH+gg13v1D+A6MqgE4gCdr/+5HRzxhv/NaARRpK5PvnjQsbRSpWRJlkSYWS4qhCqcwSw/tV04kTrCzn0a1jviy6UGrq6ZxU63MJZfSRv6TTl1dN6vmFsSJqTqQjqlBy3wLy865D3Yt04iyWQJJlEsofDbME0AgkUb9uxngj3WBvMVNOYkWUSZZUKInqnIpOIAnaZeSo5YO3WujQzWa+u843UPlbDdo558vyCNXo/4uvik4gia4/OCQEYrEEEGlVCCUdcZ2v95VVdEJIdIIEYnutitHNPV+WRahg6ASSqCmGvjLN1HLqD1eZUFZEaVAdgZMGzUrZj3QUBDqv2gmG7Ktbx3xZHqFuzhZIRop0VBVGrevSTS0/06knnQF+cayIegy5eNVZdY8yK5QZdPMvFIsvlDcdcJfOq0AgM6kHZGoFK+vmXygsoUyy+EJ5nQHS+WDHAx1yrM72UrLsERWK50YoFem0GSyhTGIJZZLnWqhQ6ITS9VsOLKFMYgllkhUl1ErGEsokTyQU/pZf3fISVTW9SJU7dgraqVqMq23d9dR/559ts53vqC/k/w0sBKaEwqJrxOK3N+6k0podVFReQ4VlleQor6aS6kbxvI3bdWOD8ZjNihqyu6rEvZbKRB2i1YgXoBu7HJgSCguuaGhlZzqPdtOde/cI18x339HZc+fJWVnPjj1JFMAmBIYwnT/uprtem3fv/Z2OdPVSSVUDR9dKiayQQmGhlU3tQow62vXqXnam80dHKSIqhpyuCmrf9TLlFbuoVEQWHEOUAKQk6hLYgJiMKBvC15KzooptuodGaFPEFi6fOHWGbZbVNhnjvGPZVrPfJso8D555qW7pYOCPfKaOR1rz+tAH6/KuB3bw8oK9GFNCwamCkgr6SU8fO5KQnEIbN0fSlph4SkzNoMxthZTvLCdnVT2V17cwSEkI4RBpilRFmjpc1ZxeuBeUbqfsfAcd7ephm2HrwmlN2DouD3uOs017WRUVb69jGxjDtoRNCSK5pLqB7+hn1Bs5GvFi8cxYgzE3ymjHC/Ctz/sc6Y99N1i6mxIKjm8rKqOteYU0PT1D4xMT9NLuVygmIYkSUtIo0ZbBDg6MHGdBgVuUcaVmbqWe/kF68OAhffLpZ5yud+7eo7aO3dTU1s595FXqcvF9cHiEktOzWaxfv3+JHjx8yOO+unmLquubRBTv4X51TW1C7CI6ffYc14tclVz/2TvvijH/oPStedS+ew/Ph+urW3+lhpYXKddeQgPDHrb7249+z23wD2IhsgI1AE8UUUlpWWQvdtLY2HU2Pjl5m9KzcygyOpbrnpOnKD0nn0EZ1wuRUSKthrnsHhymzVui6dqf/kwTk5Mclb39/dz2/TVhDK6BwSHxEpLpwi9/Rd9884CKSsrIlpFFV65+QDMzM2RLz+T7uZ++RbGJKfTlX27wuOFjHlFPpsnbd+i9CxcoLTOb+x3qPMJpffWDD+nLGzcoXrzcEc8JHnPl6of06t794qXYOQqRqoEagJBCAeQywjorz0FxyTbenwocxTQxMUlj169T+IaNPOnQiIejC6CMK2xtOPX0Gim7bv0GCt+4ifr6B7i+Nnw9dff0clkVqq/fzQJPCychLpwEiSmp3L5v/wG6ePESjY6NUX6hg5/9/O13jHqBnevb8vNp34HXuRx4wVb/gJvLybY0iktKpeyCIt5nnzqiADY+5DU2WFtWLkXHJ/Fkfd5okHsLnMIbBSjjgvNd3cY+FL5hE218IcIn1A/C1gqhjDZVqJ6+fu47PT3N0YUXEyGiNinVxu2v7d1Hza2tXD51+gz94eOPKTsn11cfHx8Xe956amlt42fRMbFse83adeLlGC8Lc+CKiIolW/Y23jv5mDOfPQrhiM1vz/6DdODwEcoWexXCH2/wi9FR3ojHxyc4utLEnlTkLONow6UKtWHTZhEp0b63yUJ523RCXbp8me7fv08OZwnZRBpdvnKVpqamKDYugSMVQoK9+/bzGv4mBEL99Jk3eS7YQP/fvH+RooRYsfEJlCsiDW0y5fHScwqdfHbD13BeXz0cCvHlOHjkKN2+c5cnwKb+x2vX+C1jr2nv2CXEmeA2iIRUwIW3CEdwIZ3wpcSegUttQxngev3QYbGXxfB+9ot332OxkIZ4EUg1zIfIvHjpMguDCIHzZ948y+MLi5wUFZtAkTFxlG8votHRMX4+NXWf+t2DHKEHD3fyM+xX+GJjHw70XcWkUG38GcVXJFbkc2R0HIcsFoPNFJNh88XC4BxA5EAYCdqQkgmp6XxHXW339RO2YTMpLZP3OpTRF85tiY3nOmxgzuj4RH6GO2xGiUiLjkuk+OQ03iJSs3K4jLTFVoGPDq8hJZ3XC19SM3PYNxwNAn1XMSUUNnOcV3IdpSKfc4UDmfwFhHBbC4r5eZY4E2FxeA4nk9Oz+BOfkmGAfQBfFvTHHXXZpgL7sIX9EJ/srDw7HzFgL02MwaaLNswJO/jC4hiBM1lGbgGDOQpLtzNIK8yF8Vgf7OEZxmIc7GBbgf+BvquEFApgg8MJFnmMwxl+zpOHQZw9XHyAa+A2POd278FSgjZ5IMRdHvYCwXPYctU1Mzg8ygMn2jAfznU8p/dgiYOuPHiijjmQSkCumX+OFHbQF1832TfUQVPymFDB6D92inqHT1L34HHqGjjG9IgynhmcmNXW5T5G3W6PH9GG/j1DJ/iO+qx2tZ/oI+2i3D3oMeyJNjzrG3nD12bY9NuVc/SNnBRrNvrxuni8h/saY9W+b2h9DsQnlEUoOuj/y4In8fRwRYAAAAAASUVORK5CYII=")
A_Args.PNG.MouseHaunt   := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.HMouseHaunt  := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.WorkerTown   := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.HWorkerTown  := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.TDS          := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.HTDS         := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.Mineraland   := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.HMineraland  := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.bombheroes   := Gdip_BitmapFromBase64(0,1,Data.PNG "EoAAABGCAYAAABrEgIKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAef0lEQVR4nO2cd3Rc1bX/P+eW6ZpRGTWry3IjlisGgY1cgNASbCBkBTDFfr/3SIIJpJdHQl2PZJHEySMJ75nmQEKCedgmhoAoouMa2bjKVbIkq1qa0Wj6nXvP74/xCNmY2BCw89Z637W81ujec/bZ+3v3Pmeffc+1mFF3ruT/cEJoAD6v93Tr8U+NwVAoTRRAoL/vdOryT4ucvHwAlNOsx/8a/B9RJ4nTRpQixOka+hPhtBB13oRSLpxShE3/3+PQ2ombfLpQFMEV8xw4bZL3diskDetUq/CJcEofqdOmcvGMcupqA/iyQljWBylcmXDTFzmL5NBEbIHcU6nWSeGUelRNiYevX5mNTXmHlFLG6LJ8RqkmZvhz/LTwX6grLiWrX9I3sI3UjlV4olswvEOnUsWPxGdOlN9nIzfLzsCQwRlVORT514MzRJHLx51flOTleFjS/e9c94KfSx8DRYWOM+rZOP5s9iRfwdqzBqe5m5Q7/Fmr+nfxmRNVXZDL7ddqeJxdYPaBPQ9yf0kuvyQ352Va39/NxXf5ibRBqwIo4N0Ml2+20177BbZV1bM9axPWrufwRraT8A5+1iofF2pJadldDrudeCz6mQwQSxrodjszaiX+7H2Q801wfwncm+Dlu2m/8yxe74A+wFQgKSGiQEAFbzdM3mOnQlSRmjCHzqISlI4BHEYY05b8TPQ9Fk6Xm0QicSqIMtnfnqDen0v+mAOgV4Jwgvo0ON4irygHR3g0ne0qAQmGhLiEhAVRIAB4e+HMHTqj7DUEJ8+kN6cSV2sCXQ6R0uOfid4ZZIj6+KGXNLFrDrLcdjweHUVIYjGLYChKNJVA6OpRzfO9Cl8bP4/q0d1Y8cko6m8h+hjmW9cQjPlx+1LM9MVYk6/zjn0/OdEh8gbs2BBYaCiodAL5VFHRBNc15bFx+qW84q8kenADuvU0tvxubA71+Pp+SjhpolwRg3lTq1hwfSEV4yLkZCeAOKRSIB0E+8vZtsnO7/97E1vigBDQ62R3zn/yX+V2xm3Zwdjyt6E0DKIThVwG3rbx3vMWd9R5OXDxozw+5oeMWXQdjr5DiLBOLGGQUPLo37SeNXdOZV/8UQTgb1rE8v/IYvesKkJvnQ07EjQN7qAj0E8wPEhSd5x6ohQE02UvP3pwFmUXAOHNsPcA7AxDWIAUYLPILvZx3oLJnHfxPO695kleaD6HLeevonDU77H/JsrByW2Mu3MjtIzn0NorcV13FWOueZ/iDX9kUtOz2FZs4UuXFkBpO4ReAp8fNAkOA+bNoX/bYzzzh18Ar3DpfcuZ/oOFTO9/Hs4YBU43ROyQmMbONYf5/asBlDwnLl0jFErQN5Cku2+IQDRKyqYgPsH2ScyoO1f6vN6PLLNkxYd47Asxqn56Gbz6X7DZB7o7TbEiQZAmKyUh0QWzR4P/fP71tjb6tDLul8v5/nNPMefCNr769UbWPXcmLzSWcvmsucyeNRrqAP/j/O2uxRTOnEHpORWweiU4c9Oyhw7DFddxaPdWbrqqhrE5UX67X4FgK/xpN2Tr4LRAMeCMOTDjZkj+AaQFlgaGDZKCxIBCS4uTd99O0PBqK/vjCYR24nw7Jy//6HrUR8FQHAwG9sHeJAyMBWcAHBKEkg67WABsbnC7wVkKr+2Hq8/insuHiL/9MFUPb2dMfZiXXjnE9i2XEzNdlE3OQnWliK2LIV6xcMxcxPTzgxy2PQSyFDwq2PT0vkHPhx1rKRk3j9rSR5j1lTrImQTPvgjeElAtiAPBbhg1Gg7vhedfgJgGqkg/UJuBvcjL+Opqxk+t5KZFFfzliQgPrthPyO06KY864apnolEdPcSkeWPBJqGrE3QdTBNLF5jj61FkCgI9YHeAZoehGE69H+/Ce1AHvkD55gT7UhEcup8Z5xZQUpBL+wGLrf39NFuH6d7cjRWcTMq3nWzHG4iEA0w1TZSqQV8bjJtOsc1iwmVFeORu2ByHrAwZAqwhmHA+uHNh++sg8kHzgiGwXOWIPgW2HIR9e1G0A0xYPI+pVpx1azuI6B9N1kmvelKBAwEVgmHIzgMzDtIF8QCi5gtgH4UclYewgGAX2N3Qu4cBt4/c2Nfh1zDBW8ZXF6vsDB9m4/NBDjQP4S7SUDQTlQRChpiwU+Ec00aBqx+3vxL6DVABJLizYP9aJn3th+BeAw1N4MkFh5IOT0gnYaoOwoQcDQwVZBhKx2O6J2BFQmhFB2GwBdrssOYRJi3+V27etIv7tplY6t9fNU8cpELSknRgdQfBkwd2E1QFbArC7WJo9UPEWjrg7BkgDLACJJIJRMlctJ0qVnOMgXkB/P8mmPwVF1c/UMH4eTn09YQJxQY5NNjJ3r42Ng000RWNkRr0gZ4AlwIuDWwGeO0QbAexAQa6IZ6FHFUEDi1NlkMBrxN0J4g4eBRwKqDHoagKNSTAXQBnjgE9jnT2YZkSojpjSxWcRuyENJxUetBu+enY1Ur5rAlQ6IGkAM0G4f2oV38PpeogdL4FNgHVZ5EIJtC7c5HbYOiSPp7qOEDbv4T56f/Uo5zhpbxG5xtzd9N5KIDlDBCJDzJKGyLHb6AqWlortwbJAFTPBTMGnWth81OQiCKrZiFGXwpb7gdpS6ciWjYyZUJqAJHjgJAKSiGy5y04eyqaLwTbmyE7F8s/Bww/vNZAsqsDRas9IQcnVWaJal662npBSUJRHtgV8GZDuBtv9XociZdhfxA8OowqxV47DjHQzUBbP4HpSdY+f5AzJuXTsTfGd+Y/Q9PmjeRN7Kcv2Y1hDZLnksyo0qktNRGOOPj0tEc54pA3BiZ+EbLjoGWBPQXeceB2wigBDhXcCuS4IREHI5Du71bAkwD/aMw9LuRmA2IucKdQK1yoNRPo23SI36/XCWv2T4eolGanvd2AwT4ozgM74LWBO4m5YTdmx1mQ64dsF7Q9jz2rAcu3l56+LXTsNLnnyc9zzQ+r+e6CP7HqL2/QE+glFBrEQZhcm86EEhvnT7NRmBXDKHHCqCywC/A5IbIHpA+qa8AWhfKxWAGQ3RuO6CLAYYI3G4kDpPFBONrDiKI62OTAis6EyZ8DHdi3HHKXY//uzQh7LlKe+NXmSRFlKbCnX4XDESjIBncqnbvk2RH5F0FXIRTOgiIbuHLgsBNdbMdd8ybh/dm0bW/nxcb3KK2PcssDY+nem2Bwe5QJRV4mlzv54llRpk4yCMsBtDEzwS3ABjh1sIUwd7VB9hjI7QbPeKyOPqx4Lzhsae+2WeB0IxNGOrdzqKAroPkg2YR2bSnqrG6I7T2SyoyFre/iLQpy+43VZEd6Px2iEJL9cQf0qOAZBd4E2FXwaQg3BJY/TvIQMGkG2OIgbXjOKSGr6l5qlBf522+6eOnebRQIB8a+FO1/GWJioZvPn61w3fm9XHqZA0vsItK7C09OxZHFQqQ9tyAPeWAzstuLVTkXmahAaWlCZOWA3QItAUoQZAKheMDhRCZ7wDqcJi26CcFvoXMVtPUiCWKlOkm558E+J97BPeTYT1yOPum9Xof00buvjwLGgk+BiArxPsjW4MafICf1QHwjKHawUmDz4b1EYjXcy5eLFrO5tZI9PQME3XDRmSk+VzRIaVUK12gnqUQbA9vXkq2kIJVCKiFIRpEIsBeiulsQb+9EnHU1HGjECu9FtV2GNL1IzYvUahDuOpTIftgWwSy+GjwglFh6IehWQNiRTgVp2lAMO1qXHfauomV3P4PKGZ8eUWHFS3dbHwXSBm4XDEkwsxCJTfivOBfk32BnEFRPukwZOIBW+f/wV75DctcdXDj7y9S5qhlI+Bhni6A4hsCMMth1EFvPRmIdFlv74IKwG6F+CUQPImzAbkkq0kVq6w4cW3cwEIB2D0w+2Ae9kxBDAUiZ0L0f9q6GUBK1cjpk5aXzKqz0LkKkIJWERBgi/dCyiwP74Xe7XARUF/D356mTJsrQXbS172bSYSMdflYP2FzpQZufgqQPpBccAuJtWL7pKAcV+jftwynB1bsCl91LoeolIXRMK4keD+CLRpF98GAT5DoVLmj6M4hyCByA3i4YglAH/LZL5UDRxbT1m9zQ/RKTX34SawgO9UIwkd7aHYhAexAqPH8jz/ZBOqUA4SSEBMRSMBBV2Z5wsSlezICejTwBSR+LKEtT2d+rQM8gTCwEtSMdZjgh5QA1CWYXZlxFeuaihSfDuj/w4rtDbInAD84Gf0EItBB2C0hCNASbW2FZ/1genfIEc0JLmfrI06TMdg4r0KVnMWD56TGq+eMZ9yJHnwMWBDd+n841T7A7N4c3XJfQ160TN1NYlgfC4yFwCMXejdcRwZuXQk3GCMS8BGMOVMWOzaGSq/dRZG06WfNPXD0YiTnGTn7+68tgTglyy38jLW868dSykFohknzUaBYiAOx8ls7nB7levYzGCUup3f4b5sReptDWTVI16bL87NHGscGoJ+a9FJzF0NEEXRuhKh8qJwNFUJAPdg/s74LDB0Go4B8FLgFCoHZG8eRqOFQdh24h1CiDcRtKVEG4Bf3buhFDSayJZeQXuTCCcUI9caxQAM+oIUr3/w632fqRNp909WAkWsiGbe/BqC8DV4GZRDEkCA/ETIgE4dC7sKGTd/bAPeICGi9eA7mCbbZfs23PNujtANMivf7nwigf5UoP43N34q4uZ1dgHM07DsNBHeZVwYbt0LyL0dVOykb7MJMx2jre52C3DqrCpfUelt9/Ns5kAk0ILEUQNQHF4p2dCa5e3MT3ri3j2htyKc21EY652dce5bXnwizfptBV/kVqWh48oe0fi6gB4ae5aRvjrV8hssakC2DJEAS6Ce6GrQOwTrfzdmQe77kWMJB3Gby+Gbr2o+XZ8RfkUFZfQ02FF6t/kPpCyexpHvIriijw2QFBAmje7+N792/h5Qceori2hKX3n8l5c0Yxyp3OZg4NGbzwWjc33/Qy2vjR5GKk61YW4FGw2zVQoCxl8siKy1hYrUC0FyImHiEo+pyLcYVn8ODN6yB6cjX3j0VUVLNz9+ZsZh0Mk2MdIBQRBAUM6D7eK7uC94JTkYECcJRDbhZnau1MqdOZVH0GZ07Op7zURYnfTnqFyQdMMILQHwKrENxR7IEBJo/O5nd3TefcbpOXls9mkl9AuBdiAmJQIgT/tqCC1ocvYd22AUhF01mxpbOlySAQCJLncVA6zsWU/BC0hdMloNx80CUQZ+2aAwypBv5Ux6dPlIlkrzaarf1eBhwVRGwFJKP5JBPVyMAYxo9zMaVCcsEEhaaQgmdMBT+b6SVdW4+CFYfDEYI9NvrsFmO8UXDpHArnUPeVFVx1UQ6/+u550DdIoSloeOoCJrkHoT0AWcX0H7aTlxeCeAT6uvjmuVn8ZXQuhCNpBR0qv2yOsubtfYRTOi98u5bP+wX4Xby8CX7w6KvUeFNcc8MsDsQSZLsknrb9nz5RAEnhp73mq0QThZjOHM6s1KlwRlj9q7f5/r9fyU31RUCC8dsiPLQlCFPD6ZxL0XhorWBDr8rGbQe5ss7GPV8eBckEQ5pGx5tv8mrJDNDcwCCeHJUpoh/6E5BXwC+WH+Anjzdy+ZdqefK2aWiRCDkpg/OzgJSAFECU3y90Eb/2IqrubKIrEAYtByIpsvIlZbVuAv1D/PgPe/DGDqOg4DQ6PqhpfZpEBXOmYhlubptoMP/GAuonZAE6+h+b2fPCLqh3w0CISlUl264hoypCSDBNymt0Jp7jobsvztu7g6BWQSROrtnH0nf+g4WTPXD4EEgH7x904nWHqMoV4HLz8+ffIbppBX92wqO3zUZTw6iqwC4ssCQgIWlD6B6cikL/6lU8fjCfG+fdDo4ezim3eO47dYBGx+Ehlvx8A1tbk+RjJ/0G8e/jY59m0eIBIv0GE6f4qZ/ghcEesEyqPHFe3doJuMBUKMlRyLML2sNWes9lKVxWbuO8fDt0DNLSOwBokJQU+BRun+nGLwbBpvL6LpMZ961nKGGAXYdkiDu+Vo97xoV87+bZuPQ4WCbxuEZ3hPS8k6vxeqtKxXXvUHDjs6QO7uLN55q4/CfvsnmvCnEP9PVA5yFK/QpfnjoKqdqJ2spOyu6PTZQr3oYiDV54uxMw0iVXRSW3xmLj2u30xJT0jt6V3jfvD5He4Hp1fvRchMLbdrHdtFM3uRIrEgUXDPYpLH91EJIWKAJnpYYI9vNuUwCcWdAf4JYLS2h/78f87LoJ0N8D2S6e3G9ndXcynX7HLPwFKb5yWSFXnZPDgl/eyZ0v/pwDgwGm3bKGnDv+Rqd0pwuCqRReoYJdxTyJWhR8gtBzWH04nUG2DDmJDiZwqQL6e1l65/kM/eBCChNBiJvgValyCQajEhQBcYPzJwnqx3mZOWE0r+wz6eo6TEmFzpCusujRPWTrBSyY7aXOo7DpwfOZf28ThWW5XFlfBMYgOTKcjpL8fLZvhx//aTN3LSwC3QcDSWr9Cj9bOBqopWGPpK4wxl1zv8C6rR3s7Yvjtaz0myNs7OuLIVIpdOPkjhV9gtMsEqdtgP19fjZuHWD2OV4YSHBOYR6bOjX29fZTky/AkpR7BQMmYDMhJTi/ViOdaMawRQTO4hzQVXKKXSwwunnpL4OcW3cx0T0B4hGLc21DPHD/G+zdNYnZ0wqpyHURjkjW7erhqYYduHoiXDx+Eqgq+HWQJqSGYCCEEvHg86TgcB91NS7qznDBQCz9KqxL4e2DAZAWrlTbZ0UUOBOHwDaVlrYYs8/LgXw7f349xDW3vM4DP6nlO9eUg2Uws1Rnc0gFQ9A/YDHQEic8FGcoavDuwSG2bRfYkxaxaBJjlJN9QYPv//AtWhMpegajJHOLCdW4ePDlg/yhqZOsCjcB06DvYIigt5BxZR4aXtxLlt+Nx5Q4HHZyvDrC5mDNhnYGex1cNbcYocXTFYa8LOJDXpb+eTNrDfB2vot2EhP5Jycq3gkCdrfFACcIk0m1buaNMrB2ddHbO5b+bYNs6o2yKRLnF0mDrmCYnkiKQAzCcfAYFn1CwfDZsQctzKwaUnkauX2dBD1FWJV5oGeBTYPp4znU3EZZYxjNyKKkN5/SmJ3gxbv5UechAkk7DlUhXwB2jTwnEInw2vuSN7cH+PyEHEo9GvuC8Nb7zbzaP0i07TCjB188aZs/1qY4AxMHu/w/5NISN9//ai1tzT3sGUiyuaMPKSHmyKIllKIlpqKEbbgHoChkxxb1osXcSMOBLaoj1CStZyp0XOSEfAE9pPMhQfqdXiXggLErLaY/bZIb0HAi8KQfDwd1OFSeXvQKEu1sKHyNXvcmDLwIoZFyFRDPGYfhdWPTNEIpk6xYCEfPNkoP/w8inXz9XWQ2xZ+IKIC24htwV9WhRqIMYWHFUqQcYAV6sUW6cCRsXNxyAbl9Y1FSOq5UenaSgAEkj/wWSDpKTNZfCbsu0iDryE0nuLanmPdIiimbVEAnqaTLXXaRfuPuUsAbl5TIFn5d9ls6/G9+SM+oUkLMVoxEoJoGjlQ3Ttl90nb+w0QlhY/e/LlIU8ER68EV78Bu9qGJD2JeSZTwxZ5LGB+6mn5XNkmhYiQgaUDChIRMn7BzSgCD5hrJzjkKiWxBdjtMX2lRYmgMItAUcB55O6U50kR5jCDd2ou8VvooIT34sfQ/WfzDRH0clIXHMKX/EkpjlxHX0xVOIwEpI506JQDDhHRB1sIEdAQGAuOIFzkE6DbQHeC2Ypip3TTlPcUWf+Nnpjd8wnrUJ0W7Zy/tnr34Y89ydu/lVMfmE7HnEHOo6AmwG2CI9LFE01JAgqGkz164BNhUUBzg0CTeWD+7sv7M69V/xBTGqVAfOMXnzA87D/FCxUMUR15hVs+1FCbrCdu9JOwK2hHCTCVdVlIATQHVBooNPGYcEttYXfZr2j3Np1Jt4DR84gHQ5d7HM9X3UDM4jbq+q/FbZzPkyCLuENgMEFb6FI3UwSEkvmiQ5qwVvFz9GJYwT4fKp4eoDPb5mtjna6JmcBpTB+ZTZNQTs7swNBXFAlciQkB5i2fL/nhavGgkTitRGWQIGx+sY+rA5RTEP0dU6WFtzrM0+RtOt3rAPwlRGTRnr6M5e93pVuO4OEKUxLIspJTDJzuEEEf9+0eRkS2lPK7cY+8f2/fT1OWTQJMSLEtiGAapVArLSh9YUBQFVVXRNA1FUVCUT/7FmpQS0zSH5SuKcpRcy7KwLOuo++qRo4KmaR63z6mGAmkjYrEYDQ0NbNiwgd27d/P0008zf/58EokEpmme1Bmij0KGhFgsxs6dO5kzZw7JZHLYiy3LIplMMmfOHHbu3EksFiOZTJJMJj+yz6mGllbUJJFIUF5ezu23387y5ctZtGgRS5cuZevWrezbtw9Ie9nIMIB0iI4Mm8y1kTBNE8MwSCQSADidTuLx+HBf0zRJJpM4nU4AEonEsIyRfZLJ5FHe9FHhO1KH400lI9sea8+xfTKHN44QJUmlUkcZ9fDDD7N06VKKiorYsWPHsPtnBI8MD8uyPuR1IwfOeEwymf4iKpVKEY+nXzzquj583zTTOVIymRyWnemTIVMIMayrEAJVVY8i/KO8LdNWVdVhL860z9gzchqAtGOYZtqDFQB5ZDIfiUWLFhEMBnnttdeIx+P4/X6WLVvG+vXraWhoYMmSJUSjUWKxGHPmzKGhoYEHHniA9evXs2LFCmbPns2yZctYt24dt912G/F4fNjA+vp6/vrXv9LU1MQzzzxDTU0NiURiWIdUKjVMbKaPZVkkEglqampYsWIFzc3NLFu2jLy8PKLRKLNnz6ahoYE77riD5uZmhoaGuPXWW2loaGD9+vUsW7YMv98/rHN1dfWH5EQikWFb1q1bx4033vjBvD1txtny3PPqZUFBgTwWjY2NsqysTObk5MiWlha5fPlyWVVVJadNmyZbW1vlk08+KYuLi+W3v/1tKaWUt912m6ysrJSrVq2SUko5f/58uWDBAimllHPnzpVZWVlSSimbmppkbW2trKiokMuXL5eBQEBWVlbKW2+99UM6ZHDrrbfKyspKGQgE5E033SR9Pp9cvny5fPPNN2VhYeGwDo8//ricP3++XLp0qWxpaZFTpkyRVVVVw+OMGzdOjhs37kNy3njjDZmfny8DgYC86667ZHV1tayrq5PnzqqXU888S36IqFtuuUW6XC45c+ZM2dTUJBsbG+X1118vpZSyvLxcer1e6fP55J133ikDgYDMzs6W3/jGN6SUUrrdbunxeIYNdjqd0uVyDRs68rfX65Ver1eWlZVJKaVcuHChXLJkiZRSyokTJ8ra2lpZW1srJ06cKKWUcsmSJXLhwoXHJdHn8w3rUFxcLJ1OpwwEAscd54YbbpA33HDDceV4vV65cuVKGQgE5I9//GNZU1Mj686dJadMnyGPu84KIdiyZQuPPfYYc+fOPSosR84JmTDJ3D/epJi5NzL2R84XmfYjV7PW1lba2tpoa2ujtbV1WFYgEACguLgYp9OJy+XC7XYPpxDAcJvMOJm5NDOOaZr09/cfV45lWVx//fUsWbKEK664gkceeQTLMj+Yo44lSQjBtGnTWLx4MY2NjTQ2NhIMBrn77rvJzs6msrKSRYsW8fjjj3+or6Kc+DOvRYsWUVlZSXZ2NnfffTfBYJDGxg/qSrqu43A4cDgc6Lo+fL2xsZGWlhbuu+8+srOzyc7Oprq6+qgHlJmUV61axTe/+U2qqqqGx2lpaRm256PkzJs3j1WrVrFy5UomT56MZaUXOwVAkDawtbWVBx98kKGhIZ544glaW1u58cYbCYfD1NfXU1FRQVNTE6tWrWL16tXcc8896LpOKBQaVlJVVQYHBz/kYcFgcPj366+/zmOPPcaBAweorKykvr6ecDg83E/TNGw2GzabDU1Lbx5CoRCapnH55ZdTXV1NV1cX7777LvPmzTtqzEzfb33rW6xevZqVK1fS1NREZWUlCxYsIBqNYrPZmD9//ofkKIrCPffcQyQSYfHixSxatOgDJ5h+Vp10OR207N9HLBY7aunNPJ2Ry6Y8spxmsnZIh58cscxmlt7Mcn88rx1JZMYLLctCCIHdbsfhSH/FGY/HhxPNTHpyvGx9pG4j9RqZAmiaNpx2pFKp4Wnjo9IDu91O1egxxBMJtHQjFbvdfpTRGSVUVR0WkBk4c0/TtOG8ZuSAGaKOTTkykCNynZFzVaa9pmnDISelHDZOVdWjHkKm70iiMrpJKY8iQ1VVdF0/ikTDMDBNc/jBwwdzqaIo2Gw2dF0jaRhokG7kdDqHk7+RXpN52nJEQndswjnyeqbtibYaI9uPHCNj7LHkHE/28fqONDrzsEZ6VCazz5Cd0TEj/9gFR9N1FCV97BFFERQWl6QHG3GUWJBJ+0FKhu9nrh/PS0auiCdzLHmkrJEyPkp25u+MHseOeby+I3XO3B5pT0aP4T7HtBdCpMssg6F/jv//5J8Z/x/JnFSWPvPzoAAAAABJRU5ErkJggg==")
A_Args.PNG.Hbombheroes  := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.Bombpolygon  := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.HBombpolygon := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.por  := Gdip_BitmapFromBase64(0,1,Data.PNG "B8AAAAUCAIAAAD6C3GtAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAARnSURBVEhLtdX9UxpHGAfw/gePaKIxFbUtgy8EFBBO5FVsgraGoIT4lnjiCzkZ4TykhPgWhRNFFBWDSqUoKkgx1lF86cs0JvuX9eykSW3aqe2MO/fL7ex+bu+53e99Ir7OdqELVTKhWiZS10hqFZhWWVOnrtaqJBoF0y9QYAKFVCCXCmqwCrlUKJcI5EwPJlBeXMyAKo28WquU12kUX9Yys5jbSlX1xRQV9kEv9eG8uT5V2NEcHXu6E2jf9GpCFJfGs1x6oBpgoB4I/S3bPS6pAZsRnAZw67NGmjheXLlIGqNj9tSSK/2yZcOjWCQLJ1phqOGSXuLDy3/Xm/7Q1SGqlMbBdR9sD8DSpHVgWz7WiR/MY7wsinlAOww3c704w/1Zly+S7Kvo2mWyyNsNjlYOpZ315KMlOArC3jygCByFQTchB1d77mSv6r/qxE6gZYPmBYeLvWY7zUNh2J9mmVqVYq2pUtOie1gfn2KjBCwtFoqm2jhzw/rIJJlavJLO1P3J9kJjzG+N4MdRLorBrLuIxSOAQwHPBndsUO6CslHSLkNJQLFCT7SZ0bt2Vhi9dWPy73Xmq96Z65WGXJo1mkr69g9wtIeheGEymJ0jtLP4g9kSC/C7gdcN/D6ooKCUDkxwUTIf7Up/3jcGXtH9u5HG6LRyiSz6WOfQ5pt+uzrsWE6Z0akZZVp+3dX8EsvbXOkao9fHxj0WgoysxxzuKY3JzZJSwHle1dCNkrd/SijRgQGdEYfHw0+3RkqCrryJxx+vvcu5pnv9So4OG1GGQIcd59+r3m5/qm0y54rdOUJLAUbwaq1m+2Q6vTc9HajWTwLP8cP6529SsvN9Izoh0ZkDZQzheAPfawSq8YNeqZKJpx/vxEXoQIwO9e91lGBXaDqAR7FEPbkYAfweqLCAwFpWa0sk071UML3CPd/F3umnLnSif53CdNMNQOkvrb2Y7snz2/FIX4YZetqFjtqYyqBUfnPH/RzsRZGKoc1sRT+3zgYiAnjWu52h5W/jKPXZj9uytwdGdGZFZ0MzKZsw6GSN43+tTJkPLwtY+CG3LuKZ3xt5k2lFaRnaLozQbOA6b0htbAXBEvWylf15MmuBylF0b5WeMqNkHkrK0IE+cTjsTIV1UT+2SBVP/sOOVIcpfXS8Jb7UsUkH4wa0UYQ2gLBI4Asn8EkQEFBBsKqcIA3Utz1CcUDx24mtuz2xZ/jOKpVeYXYkc3T/Zb8TiYAx5itZGFHMmJbnCtAa+BycCrUpV2TJFhJlctxulTB0Zi3bFPiqdI55Xa/9iqfpfRJolgfzPBZwPNI9k6QDcL4AMfrmqufW+TKgKNhm+DfcD2GCUCwMmv5HzrxLsW/0MGDMIr42u0uPZ+F8HrxTbI6rAYaYFDMxIXq1FPN2lvt7lCHKEBm1xP1t33mYeOJ6O7OcjUDqoL8eLA94pErlkMBAE1DN4NJnPTdwPE/k8/bmtVFbIuhMhUzRCXnQxn7RAlT9Jf0a/x7X1cTi3wB5iYNtnmiGmwAAAABJRU5ErkJggg==")
A_Args.PNG.porH := Gdip_BitmapFromBase64(0,1,Data.PNG "B8AAAAUCAIAAAD6C3GtAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAATkSURBVEhLtZV5TNNnGMcfDqeDjW1yjGWDcAqKOhgR7GRQTsFtcm5QRAqCKMoUSgdy2P4klLa0xUIF8UCl0JZySLkp1AqjiB1iEYFSBCLDeKCEZcuyCW7vOjNjWMymS0yef97kfT9v8jzf9/MCGnZ7ffUXvVgaVnwpgtcbVTkQ3ziULB9Jb1N9w78Sx5VFYE3bsYt+WK0vJgosqPPh1n+G1X2OSYKwlkCsbUdRd/gFBVFyLblvNFM5ntWiStEuC6XBWKMfJt3xnG4rJjk0Z/vKOURlxdFRycHrAv9ulrWIpFNCAFYY5IcCJfpt2k5rhj8UxAF3N5RG65yKtRCkeXcw469W0DXSkulLSUNV+E6maeV+KAp/TudKw2zEpHXN2T5yTuwzul83y1ZEgpIooO2C3NhADu6GWO/RRSBXOOqwtRccgHKitSANv5Lu1ck0eRl6oIxpJsgAzj5LVlBjtRGSwv1WmGkBpID7cgi+4AW8Awb8LN8OxqvRqaOSpCGhQ1u5uYBMFzmgyzBbq5uw39s1MOHjgKSQPaGqGmM0DtIOU5eaZMvmckI/n6np+G/6076fPTzSHjnYkKcgPVRaoWvQWGqm50gFCzY4FsB6GqwrAfszTLoHUgMaNK2+Sozu56eP9vCmL+0f4r+Yrp3q+uYs925eQJ+IpRbPzpHQzFY0bKpu1V/lTNfdUKjvlgNOGeCQAU7ZsJkNtkJJpRVSG6EJ959n4yS3RdiEIlJZ6y1lmP2Drs2MpYi8poHuJ+fINGS0QEYPkn6b8P/lmuH1nvQK4cDZc1W5VIZiYJBTVhOQWKrnzgbLk1vCM5D6nZ/GvNFcDFqk3n1YfvTGaZtWnuGFQyvoRdJwO3H68b7gx7c90b2v0TwF3UtZuuXz+833gmLJBq5lq5xz1uIojtvzyHT+1PRMbZ3kUwIfHDk/DHz4ZNJjeTYePWKgRQ6a331ZFe4kiAd25HM6WxrhWndodNgF3XFFd6PRPFVLX77li8aNNwekgANb1+WIwVYKOGXCplzYeMx+O21MPZ3FbpvusV6awP1NXyhBjwiPJ3HBtWHAJqzojLko07CBntafPa/dupCO7if/OuGPNEbElKg3cOfNfKjg9K0xHrPeQQMXKjge+yK1S3ZlGE1+8OOIxx9zcWgxDy0W1U/SnFu5uudIUBS2Yqr2YpJ9U45TV1lIf3XLzOknD/ahqW3opqlCZAxWx1e704zxFL1Psky8McNteWt9Oe/v7BXWkJHaEKk90B3C2N1yrkYeomzAdbDM+ftenEg/OStaeS5JJU25LmxVxaAhMzQElFw3+IgLG5iwkQqbKHpbuODeFJq8F6m0Z98du/Fl5uAJ0uh3rKkebSK1Jvi316T1DGVMEjcotmk/ha9PlDWvRX0g5lhs9kt80yVX35lq70miH9P6Dx706SdKIuyaS4MVArqmU5v3VzBBgKzQsDoHOHtDTrhNS2C5HQaFa3qr31qSAVJCQf2G1WV7oJKCby9M+B+eeWqxNCiOhvw4HepX5DK7h42w1AKCGhOLknAoOgjlCVbCl7FYZ6iNIHXdxSPeXawYxZmc4Ybk76t8OphWglQdbiQwQgALhZxdDgwfX44b5McCiwg8gs7JGIuqw14tdGLfGdpYG1fTlais9GwtMDmfBOxQrPMZ/fX+Hq+rht3+BMs8118TOOLTAAAAAElFTkSuQmCC")
A_Args.PNG.porS := Gdip_BitmapFromBase64(0,1,Data.PNG "B8AAAAUCAIAAAD6C3GtAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAThSURBVEhLtdV9TNNHGAfwhxenk81t8jKXDQL4AypFhBEpTAYt0AoTKNgqtlQKglWUqJQO5cUWiaWtbbEDQRRRKfQNRCsgCCLiKNMOEVSwFIXINL6ghmXLsolut85scWRm0yUmz1+Xy+cud899D9TahjdXf+i+dLLvasoSRlQQK46YQotOWxOZuiqIFWsZxKihWGwItiIEiw7DrVjmGxOExRAxKhGLD8MSiD6ryARmLIlNi0lPonJY4al0QlKsNz0Ci/scoxNf6At1XK+mvIguOdtYvXNIv/myinxG6qbhWpUyQLoSdicAn/muMM5NTIbiFFCshXKm1YFkZ1UWqU2SerFaZG4vHTvL6a8lnpY41myEEtoM3V3H9WzKC++SJ/+lR56RLtRwoXQNCJOgIDlKHnxFZ/PoOPCqcVYyywKboJLtpsoiztTDTkscXkWP6pQ4qXJAvsFFGn2ibh5qh/stMN4MyAD3u4B6NAzKNs1V5ka0iV9PFwzpOf1qr1OVC1Q8kcYLnYOJeuu0jaSAqLQlFE78uoQBrT26Du1tjv7aDJemSkavUmJu+2/9+bkf2nq1NbGvscjAfWh0RZfgRLmTDU4AzjLAFcMiIXiWgkeVRBSCTID6HOsuspm9yuyh7rKxsxv7lS/XLbe6qCmXcKaM0qORmnQTt7loPAgNOppabGf5iay999gG5gM+B7xyAJ8HvjJYqNbXuCLTPDRC+HEiRX9LUzhiSDTWk9rFTv/UXTS8OY2iyC55p5mHHvPQA84vI+SfLtld7s6uVl84dLi2QCA2XOiTV2gp6eU2BBm47F9Ky0Gm934YJqHbLDQluPuwcueVg+4tZXZHt8zQfehkTJe9t4f65FYourcaTfLRvczpG+G/XvsgOpk3N6Bill/+/GA+bnkRT6S8OTZe36D/jKEEnPy7Cx8/Gw15OpGKHonRlBxNrj03QMOrUkGW+ELH0ykBDVuGBv3RnQB0l4kmBRb96Y0IdN3el5IJXjJr/x1zg/iA3w6LC8Bnl8dy4bBpLFd2aqzbbXok+E/9cSl6xHgyGkytXwkyxoyTWaDZbtcoyurNm7RMfZyN7mf8PEJG5nnszDVvBR9xChcA/kt7YqHbF0LwFwBuV8y2js5vBtHoR99fDfntdgqaKkJTJcdGhX4tCuvDXChZOUP30HE9TubjOyrie+uaxw8+e7AB3VyGrjkaNPbgunc2QWhP5Nt8mutAKrRbVjQ/Qv5h3Hm1lodMdsgUgu4whu9WKsxd8cbG4DbpAuWGl3dkZJeUaTzMGWjPvKxuGWChfifUD/yCQPhEAd4S8BHAYr7NUgUQTiZkrEcDgAbfH74Su71vH3foa+nNbktHWpLg316TJWf4w/qUPp176wHisfTOpvmoB3RyZ9/I9Lf9C2z9BB6hXNGuQDQID3ps0/V0rKmcalCJzKct/f4aSUDp3GNXlw/y9fH7Asf08LQV+tRzzte9M90JyAjFx7xnV6yDGj6xdU/a/8iZ5ymWBV8xYXeKlWAVrwJ7eAKmm0GldXAupUHJZqhMc1W/SorRIt1V2zyP7yB1SFmGqvzBxoxva8PbJK6qbVaKRBDHQ2EC5Cd5icMj5IGwOxmkbChjWO1nOdduDWsWsXuqhMOnFOaOdGNNaEuxwxEOyBIw2t/2/gZ/jzdV2obfATXYh08qa0uKAAAAAElFTkSuQmCC")
A_Args.PNG.eng  := Gdip_BitmapFromBase64(0,1,Data.PNG "B8AAAAUCAIAAAD6C3GtAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAWASURBVEhLtZX9VxJZGMf3P5haC8tWUdtc2wqB4X14Hd6ybE3LDUEjwwA1NBKRNFdF1IwkJJU4EEWEgkIyvIw4LCL8ZXsjtN3O2R97zvfcMzN3zmee+d7nufcn+EfGFzqTI4DZAg4ihtlCoVjG5UtEqIzK4HP5YgqVw+QKaTBXRKF8lbgiSUUohSKl0WRMloKHKBC+nMWSUmngOXgBTFXpHJ5IZVqVqBdW1ra79M5dDNeMbb7YjNReMwxPuurZuguMwbDfH/T7Az5/6P3HWGRnbzeZTKRSe+lcNlfM58vFIlCpUCD2cSwej4ZCMqm0SmdxhYzbz0esXlbH/Jo/brT53wTjTXLL4LSntrFPNbbULDT6npi94xPep5aAdSo8PRudc+zMOeL2xbTLTfh8h5GtQjR26A9kXW7MH8AwDJWgJ3RR16CT3T1rWQ52DLm8gcTgpM804zvTOqAffXlWNEGq73RB0AsIWoYgJwS5IWgTgrwQ5IOgT02tCYkSNwzvjz5N96gIr48giCeTLpjOqdKBs0jHlO7Z207j6vJmzLLwwe7aFvYu9I+vUdiGTu1Mg8S0Ff/8MZ74sBuPYJndHIERhTRRwP8+zBdLpXI1jkql6G62q98ONWpoMO8bXaZeRNQOvdXbZXR5fDv6Kd+AdeM8bGrXTF9ERs9duf9O27+h7ff03X+rffhe9yiiN0b0Q1Hj0J7FlltxHuF44fDIvRlrVy2QqUao7h6Ndpw7cEbZO6uzbfQ+di55InMvt5c2tlCNQ6N7BUtMHQOL9VfVq6drVmrOrvxMWq0heWpI3jMkbw0pcPZc7I6KwNLFw2K5+g+lcjFP4JgclXyjKzTPJZpFnSWgfRZw+RPm5WDPiIt/08a7a2tDhxsFI5GDg/DBQShHbBVLiXI5DUQQOxbr1u2ePZ0Bt03nnavEinPfYt3rfxC5cUvK5Z7QhYw//1L2Oe6OrRutHvvrqHnh/c2Hr4S3bb8rrVSlBeTu4SJuROBChOt8sU+IvmNwffXNgfMNoYutMYEEU2lyZsv+mDnV1bNFZwXqyBIqrUpncoRNyNgdg7utc3bpTbTn8ZovnCI1qO+Nu0jn29vv2zlyg7OB7CQ3OslNbnKz5xfyRl2Dr44MKKFfL8eEKKbqq9CfproBnR240CihUqt0hVIJPCtWbDuqjF8tLJTKhXJ5J0dE0tkwkQ8RhYBn/TWFvk5j+jhIkCcKIaKIVJlQ9WVMT4h5x8GcPWscjv9x5yNfjLKPVxVlMqNC+Z5Umenu2R80ENbJnN64p7geoTMCVPoGje661uakwi+bLq2cq3fW1n2KbO9m9rFCKV0s45UMTooSBLgmSkfyk15F2ezore7PXT2ZB7rsmDk3O4+bJ/buqcOo3C9G1wVi9/UOv3t9pfaXL3RShY5lklg2lcKT3gA2NZN75cphmWlHUPXIidyYbGEaGfDxqsqVSuK/3wcBbnPlcrJUCoUiI6NLwfD2v+lmmwcomcTxTA4PhrJj47nJqaQ3OD7ja+GaTjVpYCb/OHc6PXyFGqMwkmJ5+q4KHzal1X07TCTUcsVutP3G0jPYg9/R6y5pgRDlhGdz64AoHBUKhUAwZ7HmrLblZ86rvGGYyqrSpTxkd3g0BTyZniGWVvKe9fwLZ8Lh7OqbJ7VoIbKKwTd8T28dADrV2N9MHxoa9+D7edBNR+kMbrbE+OK36gE+V1Cly5RKHFRIxQ0gkEgwnOxQO1o4ptMX+6Gm3v+jQ03auquP6FLLg8eucDR1WDwCmzA2Zw9epnzrJjkoSpihBGKx5XwBwpdwETGLAw4NhELlggMEZvBQqVTU1iZqo4JRKpW20bhAYLaNzgMWs8E+yJcIRVKZTK5QKGQoKmUeO/OjAob/AaZ455O2a/ZIAAAAAElFTkSuQmCC")
A_Args.PNG.engH := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.engS := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
}
Save := new OBJSave("SettingsOBJ.json")
Save.Login := 15
A_Args.FontDPI := 0
if (A_Language = "0416" || A_Language = "0816")
Save.LanguageOS := "por"
Else
Save.LanguageOS := "eng"
If (InStr(A_WorkingDir, "system32")){
Msg := {por:"Voc"Chr(234)" n"Chr(227)"o pode abrir este arquivo pelos Arquivos Recentes.`nVoc"Chr(234)" deve abrir direto pela pasta onde o arquivo est"Chr(225)".", eng:"You cannot open this file from Recent Files.`nYou must open it directly from the folder where this file is."}
MsgBox, 4112, Error!, % Msg[Save.LanguageOS]
ExitApp
}
If ((A_ScreenDPI <= 100 ? "100%" : "Error") = "Error") {
Msg := {por: "A Escala do seu Windows n"Chr(227)"o esta configurado para 100%.`n"
. "1. Clique com o bot"Chr(227)"o direito em qualquer espa"Chr(231)"o vazio da "Chr(225)"rea de trabalho e escolha Configura"Chr(231)Chr(245)"es de Exibi"Chr(231)Chr(227)"o.`n"
. "2. Em Ajustar a Escala e Layout, defina-o para 100%."
, eng: "The Scale and Layout of your Windows is not configured to 100%.`n"
. "1. Please right-click on any empty space on the desktop and choose Display Settings.`n"
. "2. Under Adjust Scale and Layout, set it to 100%."}
MsgBox, 4112, Error!, % Msg[Save.LanguageOS]
ExitApp
}
If (!A_Is64bitOS){
Msg := {por:"Seu Windows est"Chr(225)" 32 Bits`nPor favor formate para 64 Bits", eng:"Your Windows is in 32 Bit`nPlease format to 64 bit"}
MsgBox, 4112, Error!, % Msg[Save.LanguageOS]
ExitApp
}
If (A_PtrSize < 8){
Msg := {por:"AutoHotKey est"Chr(225)" 32 Bits`nPor favor instale o AHK em 64 Bits", eng:"AutoHotKey in 32 Bit`nPlease install AHK in 64 Bit"}
MsgBox, 4112, Error!, % Msg[Save.LanguageOS]
ExitApp
}
If (Save.Ling == "")
Save.Ling := Save.LanguageOS
LoadGDIplus()
Data := GuiLoad()
If (Save.Login < Data["MHLogin"]["Version"] && Data["MHLogin"]["Version"]){
Title := {por:"Atualiza"Chr(231)Chr(227)"o disponivel", eng:"Update available!"}
Msg := {por:"Seu MH Login est"Chr(225)" no v" Save.Login "`nE o atual est"Chr(225)" no v" Data["MHLogin"]["Version"] "`n`nDeseja Atualizar?", eng:"Your MH Login is in v" Save.Login "`nAnd the current is in v" Data["MHLogin"]["Version"] "`n`nWant to Update?"}
MsgBox, 4, % Title[Save.LanguageOS], % Msg[Save.LanguageOS]
IfMsgBox Yes
{
Gdip_GetFile(Data["MHLogin"]["Link"], "MHLogin_v" Data["MHLogin"]["Version"] ".ahk")
Title := {por:"Completo", eng:"Complete"}
Msg := {por:"Por favor abra o MHLogin_v" Data["MHLogin"]["Version"] ".ahk", eng:"Please open the MHLogin_v" Data["MHLogin"]["Version"] ".ahk"}
MsgBox,, % Title[Save.LanguageOS], % Msg[Save.LanguageOS]
ExitApp
}
}
Data["Link"]["01"] := "https://macro-helpers.com:2447/AHK"
LoadImages()
CreateGui(){
MHGui := new classGui("MyGui","MHGui","-DPIScale -Caption -0x20000 +LastFound")
MHGui.GuiSetFont(9 - A_Args.FontDPI, "Tahoma", "cE6E6E6 bold")
MHGui.Add("HBITMAP", 01, "x0  y0 w330 +BackgroundTrans")
MHGui.Add("HBITMAP", 02, "x0  y0  +BackgroundTrans")
MHGui.Add("CustomText", 01, "x45 y3")
MHGui.Add("IMGButton", 01, "x302 y0 ")
if (Save.Ling = "por"){
MHGui.Add("HBITMAP"  , { "Label": "por", "W": 31, "H": 20, "PNG" : "PorS", "Window": ""}, "x230 y1")
MHGui.Add("IMGButton", { "Label": "eng", "W": 31, "H": 20, "PNG1": "Eng" , "PNG2": "EngH", "Func": "SetLing", "Window": ""}, "x+5 y1")
} else {
MHGui.Add("IMGButton", { "Label": "por", "W": 31, "H": 20, "PNG1": "Por" , "PNG2": "porH", "Func": "SetLing", "Window": ""}, "x230 y1")
MHGui.Add("HBITMAP"  , { "Label": "eng", "W": 31, "H": 20, "PNG" : "EngS", "Window": ""}, "x+5 y1")
}
MHGui.NewParent("Login","-caption -DPIScale ")
MHGui.GuiSetColor(242424,333333,"Login")
MHGui.Add("HBITMAP", 03, "x55 y40 +BackgroundTrans")
MHGui.Add("IMGButton", 02, "x250 y249")
MHGui.Add("IMGSwitch", {Load:"Config", GuiColor:"FF242424", W:18,H:18, label: "Hide", Window:"Login"}, "x280 y101")
MHGui.Add("DefText", 01, "+Section x22 y105 w60 Right")
if (MHGui.Controls.Hide.State == 1)
MHGui.Add("Edit", 01, "w184 h18 x+6 ys-3 -E0x200 +Border Password")
else
MHGui.Add("Edit", 01, "w184 h18 x+6 ys-3 -E0x200 +Border")
MHGui.Add("DefText", 02, "xs y+5 w60 Right")
MHGui.Add("Edit", 02, "w184 h18 x+6 ys+19 -E0x200 +Border Password")
MHGui.Add("Button2", 01, "x115 y+15")
MHGui.Add("Button2", 02, "x85  y+10")
MHGui.NewParent("Create","-caption -DPIScale ")
MHGui.GuiSetColor(242424,333333,"Create")
MHGui.Show("Hide x0 y25 w330 h275","Create")
MHGui.NewParent("Games","-caption -DPIScale ")
MHGui.GuiSetColor(242424,333333,"Games")
MHGui.Show("Hide x0 y25 w330 h275","Games")
MHGui.Controls["Edit01"].Focus()
MHGui.Show("w330 h300")
MHGui.Show("x0 y25 w330 h275","Login")
}
F01(Hwnd) {
static Make
Save.Save(Save)
1 := "Login"
2 := Save.Config.Edit01
3 := Save.Config.Edit02
4 := Save.Ling
5 := A_PtrSize=8 ? "x64" : "x32"
6 := A_Args.JS.Token
Data.Send := Data.Login
Loop, 6
Data.Send := StrReplace(Data.Send, "!" A_Index, %A_Index%)
r := TryLogin(Data.Send, 01)
If (r.Type == 420)
MsgData(r.error, 4112)
}
F07() {
1 := "Update"
2 := MHGui.Controls.Edit03.GetText()
3 := MHGui.Controls.Edit04.GetText()
4 := MHGui.Controls.Edit05.GetText()
5 := MHGui.Controls.Edit07.GetText()
6 := MHGui.Controls.Edit08.GetText()
7 := Save.Ling
8 := A_Args.JS.Token
if (!IsValidEmail(MHGui.Controls.Edit04.GetText())){
MsgData(02, 4112)
Return
}
If (MHGui.Controls.Edit05.GetText() != MHGui.Controls.Edit06.GetText()){
MsgData(03, 4112)
Return
}
Data.Send := Data.Create
Loop, 8
Data.Send := StrReplace(Data.Send, "!" A_Index, %A_Index%)
r := TryCreate(Data.Send, 01)
If (r.Type == 420)
MsgData(r.error, 4112)
}
F02(Hwnd) {
If (!A_Args.CreateAccount){
MHGui.Add("DefText", 03, "+Section x5 y60 w115 Right")
MHGui.Add("DefText", 04, "xs y+8 w115 Right")
MHGui.Add("DefText", 05, "xs y+7 w115 Right")
MHGui.Add("DefText", 06, "xs y+8 w115 Right")
MHGui.Add("DefText", 07, "xs y+7 w115 Right")
MHGui.Add("DefText", 08, "xs y+7 w115 Right")
MHGui.Add("Edit", 03, "w190 h18 xs+120 ys-3 -E0x200 +Border")
MHGui.Add("Edit", 04, "w190 h18  y+4 -E0x200 +Border")
MHGui.Add("Edit", 05, "w190 h18  y+4 -E0x200 +Border Password")
MHGui.Add("Edit", 06, "w190 h18  y+4 -E0x200 +Border Password")
MHGui.Add("Edit", 07, "w190 h18  y+4 -E0x200 +Border")
MHGui.Add("Edit", 08, "w190 h18  y+4 -E0x200 +Border")
MHGui.Add("Button1", 01, "x60 y235")
MHGui.Add("Button1", 02, "x+15")
A_Args.CreateAccount := 1
}
MHGui.Controls.CustomText01.Set({eng: "Create Account", por: "Criar Conta"})
MHGui.Show(,"Create")
MHGui.Hide("Login")
}
F08() {
MHGui.Controls.CustomText01.Set({por: "Tela de Login", eng: "Login Screen"})
MHGui.Show(,"Login")
MHGui.Hide("Create")
}
SetLing(Hwnd) {
Save.Ling := A_GuiControl
Save.Save(Save)
Gui, MyGui:Destroy
A_Args.CreateAccount := ""
CreateGui()
}
F03(Hwnd) {
Save.Save(Save)
ExitApp
}
F04(Hwnd) {
Run % Data.Link.02
}
F05() {
Save.Write("Config","Edit01", A_GuiControl)
}
F06() {
Save.Write("Config","Edit02", A_GuiControl)
}
OnMessage(0x200, "ButtonHover")
ButtonHover( wparam, lparam, msg ) {
Static MToolTip, HoverOn, Key, Hand := DllCall("LoadCursor", "ptr", 0, "ptr", 32649), Help := DllCall("LoadCursor", "ptr", 0, "ptr", 32651), Wait := DllCall("LoadCursor", "ptr", 0, "ptr", 32650), Cross := DllCall("LoadCursor", "ptr", 0, "ptr", 32515), Arrow := DllCall("LoadCursor", "ptr", 0, "ptr", 32512)
MouseGetPos,VarX,VarY,, ctrl , 2
GControl := MHGui.BTHwnd["H" ctrl] ? MHGui.BTHwnd["H" ctrl] : A_GuiControl
if (!HoverOn && GControl && MHGui.Controls[GControl].Hover = 1)
MHGui.Controls[GControl].Draw_Hover(), HoverOn := 1, Key := GControl
else if (HoverOn = 1 && GControl != Key)
MHGui.Controls[Key].Draw_Default(), HoverOn := 0, Key := ""
if (Key)
SetTimer, ButtonHoverOFF , -100
if (GControl && Mouse := MHGui.Controls[GControl].Mouse) {
if (Mouse)
Data.CurrentCursor := %Mouse%, DllCall("SetCursor", "ptr", %Mouse%)
}
else if (!Mouse && Data.CurrentCursor )
Data.CurrentCursor := 0, DllCall("SetCursor", "ptr", Arrow)
If (MHGui.Controls[GControl].Bar = 1) {
X := MHGui.Controls[GControl].X
Y := MHGui.Controls[GControl].Y
AClick := (VarX - X) > 100 ? 100 : (VarX - X) < 0 ? 0 : (VarX - X)
MToolTip := 1
ToolTip, % AClick
}
else If (MToolTip = 1) {
MToolTip := 0
ToolTip
}
if (wparam=1 && !A_Args.MoveTest)
PostMessage, 0xA1, 2,,, A
}
OnMessage(0x20A, "Funcs")
Funcs(wparam, lparam, msg){
MouseGetPos,,,, ctrl , 2
GControl := MHGui.BTHwnd["H" ctrl]
If (MHGui.Controls[GControl].Bar = 1){
wparam := wparam = 7864320 ? 1 : -1
MHGui.Controls[GControl].Set_Pin(MHGui.Controls[GControl].AClick + wparam, 1)
}
}
OnMessage(0x20,  "WM_SETCURSOR")
WM_SETCURSOR(wParam, lParam) {
HitTest := lParam & 0xFFFF
if (HitTest=1 && Data.CurrentCursor!=0) {
DllCall("SetCursor", "ptr", Data.CurrentCursor)
return true
}
}
ButtonHoverOFF() {
MouseGetPos,,,VarWin,,2
WinGetTitle, title, ahk_id %VarWin%
if (title != "MyGui")
ButtonHover(0, 0, "Timer")
}
OnMessage(0x204, "GuiContext")
GuiContext( wparam, lparam, msg, hwndID ) {
}
OnMessage(0x102, "WMChar")
WMChar(wP) {
Switch SubStr(A_GuiControl, 1 , 3)
{
Case "Num":
Stat := 1
Case "AnZ":
Stat := 2
Default:
Stat := 0
}
If (Stat == 0)
Return
If ( Stat == 1){
If (wP=8)
Return
wP := Chr(wP)
If (wP is not digit) {
Gui, Submit, NoHide
Return, 0
}
}
If ( Stat == 2){
vPos := RegExMatch(Chr(wP), "[A-Za-z]")
If (wP=32 || wP=8)
Return
If (!vPos) {
Gui, Submit, NoHide
Return, 0
}
}
}
class classGui {
__new(Name, Var, Options:="+LastFound") {
This.Var      := Var
This.Name     := Name
This.Title    := Name
This.BTHwnd   := Object()
This.Controls := Object()
This.Child    := Object()
Gui, % This.Name ": " Options " hwndHwnd"
This.Hwnd := Hwnd
Gui, % This.Name ":Default"
This.GuiSetMargins()
}
NewParent(Name, Options:="+LastFound", Window:="", Title:="") {
Title := Title ? Title : Name
Hwnd := Window ? This.Child[%Window%.Hwnd] : This.Hwnd
Gui, % Name ":New", % Options " +parent" This.Hwnd
This.Child[Name] := {Name: Name, Title: Title, Hwnd: WinExist()}
DF := This.DefaultFont
Gui, % Name ":Font", % "s" DF.Size " " DF.Options, % DF.Font
}
Add(Type,Valor,Options:="") {
obj := Valor
if (!IsObject(obj))
obj := Data["Add"][Type][obj]
try
Label := RegExReplace(obj.Label, "[^A-z0-9_]")
Catch
Label := Type Valor
try
Window := obj.Window
If (!Window)
Window := This.Name
v := This[Type]
This.Controls[Label] := new v(obj,Options,Label,Window,This.Var)
}
ClearContents() {
for Name, CtrlObj in This.TextCtrl
CtrlObj.SetText()
}
CheckForContents() {
for Name, CtrlObj in This.TextCtrl
if(CtrlObj.GetText()!="")
return 1
return 0
}
Activate() {
WinActivate % "ahk_id " This.Hwnd
}
Show(Options:="",Window:="") {
Window := Window ? Window : This.Name
if(This.GuiX!="" and This.GuiY!="")
Gui, % Window ":Show", % Options " x" This.GuiX " y" This.GuiY, % This.Title
else
Gui, % Window ":Show", % Options, % This.Title
}
Hide(Window:="") {
Window := Window ? Window : This.Name
Gui, % Window ":Hide"
}
Minimize() {
Window := Window ? Window : This.Name
WinMinimize % "ahk_id " This.Hwnd
}
GuiSetTitle(NewTitle:="") {
This.Title := NewTitle
Gui, % This.Name ":Show",, % This.Title
return
}
GuiSetMargins(X:=4, Y:=4) {
Gui, % This.Name ":Margin", %X%, %Y%
}
GuiSetFont(Size:=10, Font:="", Options:="", Window:="") {
Window := Window ? Window : This.Name
If (Window = This.Name)
This.DefaultFont := {Size: Size, Font: Font, Options: Options}
Gui, % Window ":Font", s%Size% %Options%, %Font%
}
GuiSetColor(Background:="", Foreground:="", Window:="") {
Window := Window ? Window : This.Name
Gui, % Window ":Color", %Background%, %Foreground%
}
GuiSetOptions(Options, Window:="") {
Window := Window ? Window : This.Name
Gui, % Window ":" Options
}
GuiSetCoords(X, Y) {
This.GuiX := X
This.GuiY := Y
}
GuiSetPos(X, Y) {
DetectHiddenWindows, On
WinMove, % "ahk_id " This.Hwnd,, % x, % y
DetectHiddenWindows, Off
}
AddTextField(CtrlType, LabelText, FieldText:="", Width:="", TextOptions:="", FieldOptions:="", DataControl:=1) {
This.Add("Text", LabelText, "+Section w" Width " " TextOptions,, DataControl)
This.Add(CtrlType, FieldText, "w" Width " " FieldOptions, LabelText, DataControl)
}
class HBITMAP {
__New(obj,Options,Label,Window,vGlobal) {
This.Window := Window
This.PNG := obj.PNG
Gui, % This.Window ": Add", Picture, % Options " HwndHwnd", % "HBITMAP:*" A_Args.PNG[This.PNG]
This.Hwnd := Hwnd
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
}
}
class Edit {
__New(obj,Options,Label,Window,vGlobal) {
static  i:=1
Try
Load := Save[obj.Load][Label]
Try
Func := obj.Func
Try
Block := obj.Block
if (Block)
Options .= " v" Block i++
if (Func)
Options .= " g" Func
This.Hwnd := This.Create(Window, Options, Load)
This.Window := Window
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
}
Create(Window, Options, Load){
static
Gui, % Window ": Add", Edit, % Options " HwndHwnd", % Load
Return Hwnd
}
GetText() {
ControlGetText, T,, % "ahk_id " This.Hwnd
return T
}
SetText(T:="") {
ControlSetText,, % T, % "ahk_id " This.Hwnd
}
Focus() {
ControlFocus,, % "ahk_id " This.Hwnd
}
}
class DefText {
__New(obj,Options,Label,Window,vGlobal) {
This.Window := Window
Try
FontOptions := obj.FontOptions
Try
Font := obj.Font
If (FontOptions && Font)
Gui, % This.Window ": Font", % FontOptions, % Font
Gui, % This.Window ": Add", Text, % "0x200 HwndHwnd " Options, % obj[Save.Ling]
If (FontOptions || Font){
DF := %vGlobal%["DefaultFont"]
Gui, % Window ":Font", % "s" DF.Size " " DF.Options, % DF.Font
}
This.Hwnd := Hwnd
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
}
}
class Button1 {
__New(obj,Options,Label,Window,vGlobal) {
This.W := obj.W
This.H := obj.H
This.BColor := "0x" obj.GuiColor
This.Color := "0x" obj.Color
This.FColorTop := "0x" obj.FColor
This.FColorBottom := "0x" obj.FColorB
This.Font := obj.Font
This.Font_Size := obj.FOptions
This.Roundness := obj.Roundness
This.Func := obj.Func
This.Label := Label
This.Window := Window
This.Mouse := "Hand"
This.Hover := 1
This.Create_Bitmap(obj[Save.Ling])
Gui , % Window ": Add" , Picture , % Options " w" This.W " h" This.H " hwndHwnd 0xE", % Label
This.Hwnd := Hwnd
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
BD := THIS.Pressed.BIND( THIS )
GUICONTROL +G , % Hwnd , % BD
This.Draw_Default()
}
Pressed() {
if (!This.Draw_Pressed())
return
If (This.Func){
FuncRun := This.Func
%FuncRun%(This.Hwnd,A_GuiControl)
}
}
Draw_Pressed() {
SetImage( This.Hwnd , This.Pressed_Bitmap )
A_Args.MoveTest := 1
While( GetKeyState( "LButton" ))
sleep , 10
A_Args.MoveTest := 0
MouseGetPos,,,, ctrl , 2
if( This.Hwnd != ctrl ){
This.Draw_Default()
return False
} else {
This.Draw_Hover()
return true
}
}
Draw_Default() {
SetImage( This.Hwnd , This.Default_Bitmap )
}
Draw_Hover() {
SetImage( This.Hwnd , This.Hover_Bitmap )
}
Editor(Text,FColorTop:="") {
If (FColorTop)
This.FColorTop := "0xFF" FColorTop
DeleteObject( This.Hover_Bitmap )
DeleteObject( This.Pressed_Bitmap )
DeleteObject( This.Default_Bitmap )
This.Create_Bitmap(Text)
SetImage( This.Hwnd , This.Default_Bitmap )
}
Create_Bitmap(Text) {
pBitmap:=Gdip_CreateBitmap( This.W , This.H )
G := Gdip_GraphicsFromImage( pBitmap )
Gdip_SetSmoothingMode( G , 2 )
Brush := Gdip_BrushCreateSolid( This.BColor )
Gdip_FillRectangle( G , Brush , -1 , -1 , This.W+2 , This.H+2 )
Gdip_DeleteBrush( Brush )
Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W , This.H , "0xFF61646A" , "0xFF2E2124" , 1 , 1 )
Gdip_FillRoundedRectangle( G , Brush , 0 , 1 , This.W , This.H-3 , This.Roundness )
Gdip_DeleteBrush( Brush )
Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W , This.H , "0xFF4C4F54" , "0xFF35373B" , 1 , 1 )
Gdip_FillRoundedRectangle( G , Brush , 1 , 2 , This.W-2 , This.H-5 , This.Roundness )
Gdip_DeleteBrush( Brush )
Pen := Gdip_CreatePen( "0xFF1A1C1F" , 1 )
Gdip_DrawRoundedRectangle( G , Pen , 0 , 0 , This.W , This.H-2 , This.Roundness )
Gdip_DeletePen( Pen )
Brush := Gdip_BrushCreateSolid( This.FColorBottom )
Gdip_TextToGraphics( G , Text , "s" This.Font_Size " Center vCenter c" Brush " x1 y2 " , This.Font , This.W , This.H-1 )
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.FColorTop )
Gdip_TextToGraphics( G , Text , "s" This.Font_Size " Center vCenter c" Brush " x0 y1 " , This.Font , This.W , This.H-1 )
Gdip_DeleteBrush( Brush )
Gdip_DeleteGraphics( G )
This.Default_Bitmap := Gdip_CreateARGBHBITMAPFromBitmap(pBitmap)
Gdip_DisposeImage(pBitmap)
pBitmap:=Gdip_CreateBitmap( This.W , This.H )
G := Gdip_GraphicsFromImage( pBitmap )
Gdip_SetSmoothingMode( G , 2 )
Brush := Gdip_BrushCreateSolid( This.BColor )
Gdip_FillRectangle( G , Brush , -1 , -1 , This.W+2 , This.H+2 )
Gdip_DeleteBrush( Brush )
Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W , This.H , "0xFF61646A" , "0xFF2E2124" , 1 , 1 )
Gdip_FillRoundedRectangle( G , Brush , 0 , 1 , This.W , This.H-3 , This.Roundness )
Gdip_DeleteBrush( Brush )
Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W , This.H , "0xFF55585D" , "0xFF3B3E41" , 1 , 1 )
Gdip_FillRoundedRectangle( G , Brush , 1 , 2 , This.W-2 , This.H-5 , This.Roundness )
Gdip_DeleteBrush( Brush )
Pen := Gdip_CreatePen( "0xFF1A1C1F" , 1 )
Gdip_DrawRoundedRectangle( G , Pen , 0 , 0 , This.W , This.H-2 , This.Roundness )
Gdip_DeletePen( Pen )
Brush := Gdip_BrushCreateSolid( This.FColorBottom )
Gdip_TextToGraphics( G , Text , "s" This.Font_Size " Center vCenter c" Brush " x1 y2" , This.Font , This.W , This.H-1 )
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.FColorTop )
Gdip_TextToGraphics( G , Text , "s" This.Font_Size " Center vCenter c" Brush " x0 y1" , This.Font , This.W , This.H-1 )
Gdip_DeleteBrush( Brush )
Gdip_DeleteGraphics( G )
This.Hover_Bitmap := Gdip_CreateARGBHBITMAPFromBitmap(pBitmap)
Gdip_DisposeImage(pBitmap)
pBitmap:=Gdip_CreateBitmap( This.W , This.H )
G := Gdip_GraphicsFromImage( pBitmap )
Gdip_SetSmoothingMode( G , 2 )
Brush := Gdip_BrushCreateSolid( This.BColor )
Gdip_FillRectangle( G , Brush , -1 , -1 , This.W+2 , This.H+2 )
Gdip_DeleteBrush( Brush )
Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W , This.H , "0xFF2A2C2E" , "0xFF45474E" , 1 , 1 )
Gdip_FillRoundedRectangle( G , Brush , 0 , 1 , This.W , This.H-3 , This.Roundness )
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( "0xFF2A2C2E" )
Gdip_FillRoundedRectangle( G , Brush , 0 , 0 , This.W , This.H-8 , This.Roundness )
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( "0xFF46474D" )
Gdip_FillRoundedRectangle( G , Brush , 0 , 7 , This.W , This.H-8 , This.Roundness )
Gdip_DeleteBrush( Brush )
Brush := Gdip_CreateLineBrushFromRect( 5 , 3 , This.W ,This.H-7 , "0xFF333639" , "0xFF43474B" , 1 , 1 )
Gdip_FillRoundedRectangle( G , Brush , 1 , 2 , This.W-3 , This.H-6 , This.Roundness )
Gdip_DeleteBrush( Brush )
Pen := Gdip_CreatePen( "0xFF1A1C1F" , 1 )
Gdip_DrawRoundedRectangle( G , Pen , 0 , 0 , This.W , This.H-2 , This.Roundness )
Gdip_DeletePen( Pen )
Brush := Gdip_BrushCreateSolid( This.FColorBottom )
Gdip_TextToGraphics( G , Text , "s" This.Font_Size " Center vCenter c" Brush " x1 y3" , This.Font , This.W , This.H-1 )
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.FColorTop )
Gdip_TextToGraphics( G , Text , "s" This.Font_Size " Center vCenter c" Brush " x0 y2" , This.Font , This.W , This.H-1 )
Gdip_DeleteBrush( Brush )
Gdip_DeleteGraphics( G )
This.Pressed_Bitmap := Gdip_CreateARGBHBITMAPFromBitmap( pBitmap )
Gdip_DisposeImage( pBitmap )
}
}
class Button2 {
__New(obj,Options,Label,Window,vGlobal) {
This.W := obj.W
This.H := obj.H
This.Font := obj.Font
This.FontOptions := obj.FontOptions
This.Text_Color:= "0x" obj.FontColor
This.Gui_Color := "0x" obj.GuiColor
This.Line_Color:= "0x" obj.LineColor
This.Default_Color:= "0x" obj.DefaultColor
This.Hover_Color  := "0x" obj.HoverColor
This.Roundness := obj.Roundness
This.Func := obj.Func
This.Label := Label
This.Window:= Window
This.Mouse := "Hand"
This.Hover := 1
This.Create_Bitmap(obj[Save.Ling], This.W, This.H)
Gui , % Window ": Add" , Picture , % Options " w" This.W " h" This.H " hwndHwnd 0xE", % Label
This.Hwnd := Hwnd
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
BD := THIS.Pressed.BIND( THIS )
GUICONTROL +G , % Hwnd , % BD
This.Draw_Default()
}
Pressed() {
if (!This.Draw_Pressed())
return
If (This.Func){
FuncRun := This.Func
%FuncRun%(This.Hwnd)
}
}
Draw_Pressed() {
SetImage( This.Hwnd , This.Default_Bitmap )
A_Args.MoveTest := 1
While(GetKeyState("LButton"))
sleep , 10
A_Args.MoveTest := 0
MouseGetPos,,,, ctrl , 2
if( This.Hwnd != ctrl ) {
This.Draw_Default()
return False
} else {
This.Draw_Hover()
return true
}
}
Draw_Default() {
SetImage( This.Hwnd , This.Default_Bitmap )
}
Draw_Hover() {
SetImage( This.Hwnd , This.Hover_Bitmap )
}
NewModel(Type) {
obj := Data["Add"]["Button2"][Type]
DeleteObject( This.Hover_Bitmap )
DeleteObject( This.Default_Bitmap )
This.Text_Color:= "0x" obj.FontColor
This.Gui_Color := "0x" obj.GuiColor
This.Line_Color:= "0x" obj.LineColor
This.Default_Color:= "0x" obj.DefaultColor
This.Hover_Color  := "0x" obj.HoverColor
This.Roundness := obj.Roundness
This.Func := obj.Func
This.Create_Bitmap(obj[Save.Ling], This.W, This.H)
This.Draw_Default()
}
Create_Bitmap(Text, W, H) {
pBitmap:=Gdip_CreateBitmap( W , H )
G := Gdip_GraphicsFromImage( pBitmap )
Gdip_SetSmoothingMode( G , 2 )
Brush := Gdip_BrushCreateSolid( This.Gui_Color )
Gdip_FillRectangle( G , Brush , -1 , -1 , W+2, H+2)
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.Line_Color )
Gdip_FillRoundedRectangle( G , Brush , 0 , 0 , W-1, H-1, This.Roundness)
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.Default_Color )
Gdip_FillRoundedRectangle( G , Brush , 2 , 2 , W-5, H-5, This.Roundness-3)
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.Text_Color )
Gdip_TextToGraphics( G , Text , "s" This.FontOptions " Center vCenter c" Brush " x0 y2 " , This.Font , W , H-1 )
Gdip_DeleteBrush( Brush )
Gdip_DeleteGraphics( G )
This.Default_Bitmap := Gdip_CreateARGBHBITMAPFromBitmap(pBitmap)
Gdip_DisposeImage(pBitmap)
pBitmap:=Gdip_CreateBitmap( W , H )
G := Gdip_GraphicsFromImage( pBitmap )
Gdip_SetSmoothingMode( G , 2 )
Brush := Gdip_BrushCreateSolid( This.Gui_Color )
Gdip_FillRectangle( G , Brush , -1 , -1 , W+2, H+2)
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.Line_Color )
Gdip_FillRoundedRectangle( G , Brush , 0 , 0 , W-1, H-1, This.Roundness)
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.Hover_Color )
Gdip_FillRoundedRectangle( G , Brush , 2 , 2 , W-5, H-5, This.Roundness-3)
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.Text_Color )
Gdip_TextToGraphics( G , Text , "s" This.FontOptions " Center vCenter c" Brush " x0 y2" , This.Font , W , H-1 )
Gdip_DeleteBrush( Brush )
Gdip_DeleteGraphics( G )
This.Hover_Bitmap := Gdip_CreateARGBHBITMAPFromBitmap(pBitmap)
Gdip_DisposeImage(pBitmap)
}
}
class IMGButton {
__New(obj,Options,Label,Window,vGlobal) {
This.W := obj.W
This.H := obj.H
This.D_Bitmap := A_Args.PNG[obj.PNG1]
This.H_Bitmap := A_Args.PNG[obj.PNG2]
This.Func     := obj.Func
This.Label    := Label
This.Window := Window
This.Mouse := "Hand"
This.Hover := 1
Gui, % Window ": Add" , Picture , % Options " w" This.W " h" This.H " 0xE hwndHwnd", % Label
This.Hwnd := Hwnd
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
BD := THIS.Pressed.BIND( THIS )
GUICONTROL +G , % Hwnd , % BD
This.Draw_Default()
}
Pressed() {
if (!This.Draw_Pressed())
return
If (This.Func){
FucRun := This.Func
%FucRun%(This.Hwnd,A_GuiControl)
}
}
Draw_Default() {
SetImage( This.Hwnd , This.D_Bitmap )
}
Draw_Hover() {
SetImage( This.Hwnd , This.H_Bitmap )
}
Draw_Pressed() {
SetImage( This.Hwnd , This.D_Bitmap )
A_Args.MoveTest := 1
While( GetKeyState( "LButton" ) )
sleep , 10
A_Args.MoveTest := 0
MouseGetPos,,,, ctrl , 2
if( This.Hwnd != ctrl ) {
return False
} else {
SetImage( This.Hwnd , This.H_Bitmap )
return True
}
}
}
class IMGSwitch {
__New(obj,Options,Label,Window,vGlobal) {
This.W:=obj.W
This.H:=obj.H
This.GuiColor:= "0x" obj.GuiColor
This.Label:= Label
This.Window := Window
This.Mouse:= "Hand"
This.Hover:= 1
This.Section := obj.Load="Profile" ? Save.Profile : obj.Load
This.State:= Save[This.Section][Label]
This.Create_Off_BitmapNoText()
This.Create_On_BitmapNoText()
Gui, % Window ": Add" , Picture , % Options " w" This.W " h" This.H " 0xE hwndHwnd", % This.Label
This.Hwnd := Hwnd
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
BD := This.Switch_State.BIND( This )
GUICONTROL +G , % Hwnd , % BD
This.Draw_Default()
}
Create_Off_BitmapNoText() {
pBitmap:=Gdip_CreateBitmap( This.W+2, This.H+2 )
G := Gdip_GraphicsFromImage( pBitmap )
Gdip_SetSmoothingMode( G , 4 )
Brush := Gdip_BrushCreateSolid( This.GuiColor )
Gdip_FillRectangle( G , Brush , -1 , -1 , This.W+4, This.H+4)
Gdip_DeleteBrush( Brush )
Gdip_DrawImageRect(G, A_Args.PNG.HideOFF, 0, 1, This.W, This.H)
This.Off_Bitmap := Gdip_CreateARGBHBITMAPFromBitmap(pBitmap)
Gdip_DrawImageRect(G, A_Args.PNG.HideHOFF, 0, 1, This.W, This.H)
This.Hover_Bitmap_Off := Gdip_CreateARGBHBITMAPFromBitmap(pBitmap)
Gdip_DeleteGraphics( G )
Gdip_DisposeImage(pBitmap)
}
Create_On_BitmapNoText() {
pBitmap:=Gdip_CreateBitmap( This.W+2, This.H+2)
G := Gdip_GraphicsFromImage( pBitmap )
Gdip_SetSmoothingMode( G , 4 )
Brush := Gdip_BrushCreateSolid( This.GuiColor )
Gdip_FillRectangle( G , Brush , -1 , -1 , This.W+4, This.H+4)
Gdip_DeleteBrush( Brush )
Gdip_DrawImageRect(G, A_Args.PNG.HideON, 0, 1, This.W, This.H)
This.On_Bitmap := Gdip_CreateARGBHBITMAPFromBitmap(pBitmap)
Gdip_DrawImageRect(G, A_Args.PNG.HideHON, 0, 1, This.W, This.H)
This.Hover_Bitmap_On := Gdip_CreateARGBHBITMAPFromBitmap(pBitmap)
Gdip_DeleteGraphics( G )
Gdip_DisposeImage(pBitmap)
}
Switch_State() {
A_Args.MoveTest := 1
While( GetKeyState( "LButton" ) )
sleep , 10
A_Args.MoveTest := 0
MouseGetPos,,,, ctrl , 2
if(ctrl != This.Hwnd)
return
This.State := !This.State
if (This.State)
GuiControl, % "+Password", % MHGui.Controls.Edit01.Hwnd
else
GuiControl, % "-Password", % MHGui.Controls.Edit01.Hwnd
Save.Write(This.Section, This.Label, This.State)
Save.Save(Save)
This.Draw_Hover()
}
Draw_Default() {
if(This.State)
SetImage( This.Hwnd , This.On_Bitmap )
else
SetImage( This.Hwnd , This.Off_Bitmap )
}
Draw_Hover() {
if(This.State)
SetImage( This.Hwnd , This.Hover_Bitmap_On)
else
SetImage( This.Hwnd , This.Hover_Bitmap_Off )
}
}
class CustomText {
__New(obj,Options,Label,Window,vGlobal) {
This.W := obj.W
This.H := obj.H
This.FontOptions := obj.FontOptions
This.Font := obj.Font
This.pBitmap:=Gdip_CreateBitmap( This.W, This.H )
This.G := Gdip_GraphicsFromImage( This.pBitmap )
Gdip_SetSmoothingMode( This.G, 2 )
This.BrushBKColor := Gdip_BrushCreateSolid( "0x" obj.GuiColor )
This.BrushText    := Gdip_BrushCreateSolid( "0x" obj.FontColor )
Gdip_FillRectangle( This.G, This.BrushBKColor, -1, -1, This.W+1, This.H+1)
Gdip_TextToGraphics( This.G, obj[Save.Ling], This.FontOptions " c" This.BrushText, This.Font, This.W-1, This.H)
This.PNG := Gdip_CreateARGBHBITMAPFromBitmap(This.pBitmap)
Gui, % Window ": Add", Picture, % Options " hwndHwnd", % "HBITMAP:*" This.PNG
This.Hwnd := Hwnd
This.Window := Window
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
}
Set(obj) {
ForDelete := This.PNG
Gdip_FillRectangle( This.G, This.BrushBKColor, -1, -1, This.W+1, This.H+1)
Gdip_TextToGraphics( This.G, obj[Save.Ling], This.FontOptions " c" This.BrushText, This.Font, This.W-1, This.H)
This.PNG := Gdip_CreateARGBHBITMAPFromBitmap(This.pBitmap)
SetImage( This.Hwnd , This.PNG )
DeleteObject( ForDelete )
}
Editor(PNG) {
pBitmap:=Gdip_CreateBitmap( W, H )
G := Gdip_GraphicsFromImage( pBitmap )
Gdip_SetSmoothingMode( G, 2 )
BrushBKColor := Gdip_BrushCreateSolid( "0x" This.GuiColor )
BrushText    := Gdip_BrushCreateSolid( "0x" This.FontColor )
Gdip_FillRectangle( G, BrushBKColor, -1, -1, W+1, H+1)
Gdip_TextToGraphics( G, obj[Save.Ling], This.FontOptions " c" BrushText, This.Font, W-1, H)
This.PNG := Gdip_CreateARGBHBITMAPFromBitmap(pBitmap)
Gdip_DeleteBrush( BrushBKColor )
Gdip_DeleteBrush( BrushText )
Gdip_DeleteGraphics( G )
Gdip_DisposeImage(pBitmap)
SetImage( This.Hwnd , This.PNG )
}
}
}
Class classGuiColors {
Static Attached := {}
Static HandledMessages := {Edit: 0, ListBox: 0, Static: 0}
Static MessageHandler := "classGuiColors_OnMessage"
Static WM_CTLCOLOR := {Edit: 0x0133, ListBox: 0x134, Static: 0x0138}
Static HTML := {AQUA: 0xFFFF00, BLACK: 0x000000, BLUE: 0xFF0000, FUCHSIA: 0xFF00FF, GRAY: 0x808080, GREEN: 0x008000, LIME: 0x00FF00, MAROON: 0x000080, NAVY: 0x800000, OLIVE: 0x008080, PURPLE: 0x800080, RED: 0x0000FF, SILVER: 0xC0C0C0, TEAL: 0x808000, WHITE: 0xFFFFFF, YELLOW: 0x00FFFF}
Static NullBrush := DllCall("GetStockObject", "Int", 5, "UPtr")
Static SYSCOLORS := {Edit: "", ListBox: "", Static: ""}
Static ErrorMsg := ""
Static InitClass := classGuiColors.ClassInit()
__New() {
If (This.InitClass == "!DONE!") {
This["!Access_Denied!"] := True
Return False
}
}
__Delete() {
If This["!Access_Denied!"]
Return
This.Free()
}
ClassInit() {
classGuiColors := New classGuiColors
Return "!DONE!"
}
CheckBkColor(ByRef BkColor, Class) {
This.ErrorMsg := ""
If (BkColor != "") && !This.HTML.HasKey(BkColor) && !RegExMatch(BkColor, "^[[:xdigit:]]{6}$") {
This.ErrorMsg := "Invalid parameter BkColor: " . BkColor
Return False
}
BkColor := BkColor = "" ? This.SYSCOLORS[Class]
: This.HTML.HasKey(BkColor) ? This.HTML[BkColor]
: "0x" . SubStr(BkColor, 5, 2) . SubStr(BkColor, 3, 2) . SubStr(BkColor, 1, 2)
Return True
}
CheckTxColor(ByRef TxColor) {
This.ErrorMsg := ""
If (TxColor != "") && !This.HTML.HasKey(TxColor) && !RegExMatch(TxColor, "i)^[[:xdigit:]]{6}$") {
This.ErrorMsg := "Invalid parameter TextColor: " . TxColor
Return False
}
TxColor := TxColor = "" ? ""
: This.HTML.HasKey(TxColor) ? This.HTML[TxColor]
: "0x" . SubStr(TxColor, 5, 2) . SubStr(TxColor, 3, 2) . SubStr(TxColor, 1, 2)
Return True
}
Attach(HWND, BkColor, TxColor := "") {
Static ClassNames := {Button: "", ComboBox: "", Edit: "", ListBox: "", Static: ""}
Static BS_CHECKBOX := 0x2, BS_RADIOBUTTON := 0x8
Static ES_READONLY := 0x800
Static COLOR_3DFACE := 15, COLOR_WINDOW := 5
If (This.SYSCOLORS.Edit = "") {
This.SYSCOLORS.Static := DllCall("User32.dll\GetSysColor", "Int", COLOR_3DFACE, "UInt")
This.SYSCOLORS.Edit := DllCall("User32.dll\GetSysColor", "Int", COLOR_WINDOW, "UInt")
This.SYSCOLORS.ListBox := This.SYSCOLORS.Edit
}
This.ErrorMsg := ""
If (BkColor = "") && (TxColor = "") {
This.ErrorMsg := "Both parameters BkColor and TxColor are empty!"
Return False
}
If !(CtrlHwnd := HWND + 0) || !DllCall("User32.dll\IsWindow", "UPtr", HWND, "UInt") {
This.ErrorMsg := "Invalid parameter HWND: " . HWND
Return False
}
If This.Attached.HasKey(HWND) {
This.ErrorMsg := "Control " . HWND . " is already registered!"
Return False
}
Hwnds := [CtrlHwnd]
Classes := ""
WinGetClass, CtrlClass, ahk_id %CtrlHwnd%
This.ErrorMsg := "Unsupported control class: " . CtrlClass
If !ClassNames.HasKey(CtrlClass)
Return False
ControlGet, CtrlStyle, Style, , , ahk_id %CtrlHwnd%
If (CtrlClass = "Edit")
Classes := ["Edit", "Static"]
Else If (CtrlClass = "Button") {
IF (CtrlStyle & BS_RADIOBUTTON) || (CtrlStyle & BS_CHECKBOX)
Classes := ["Static"]
Else
Return False
}
Else If (CtrlClass = "ComboBox") {
VarSetCapacity(CBBI, 40 + (A_PtrSize * 3), 0)
NumPut(40 + (A_PtrSize * 3), CBBI, 0, "UInt")
DllCall("User32.dll\GetComboBoxInfo", "Ptr", CtrlHwnd, "Ptr", &CBBI)
Hwnds.Insert(NumGet(CBBI, 40 + (A_PtrSize * 2, "UPtr")) + 0)
Hwnds.Insert(Numget(CBBI, 40 + A_PtrSize, "UPtr") + 0)
Classes := ["Edit", "Static", "ListBox"]
}
If !IsObject(Classes)
Classes := [CtrlClass]
If (BkColor <> "Trans")
If !This.CheckBkColor(BkColor, Classes[1])
Return False
If !This.CheckTxColor(TxColor)
Return False
For I, V In Classes {
If (This.HandledMessages[V] = 0)
OnMessage(This.WM_CTLCOLOR[V], This.MessageHandler)
This.HandledMessages[V] += 1
}
If (BkColor = "Trans")
Brush := This.NullBrush
Else
Brush := DllCall("Gdi32.dll\CreateSolidBrush", "UInt", BkColor, "UPtr")
For I, V In Hwnds
This.Attached[V] := {Brush: Brush, TxColor: TxColor, BkColor: BkColor, Classes: Classes, Hwnds: Hwnds}
DllCall("User32.dll\InvalidateRect", "Ptr", HWND, "Ptr", 0, "Int", 1)
This.ErrorMsg := ""
Return True
}
Change(HWND, BkColor, TxColor := "") {
This.ErrorMsg := ""
HWND += 0
If !This.Attached.HasKey(HWND)
Return This.Attach(HWND, BkColor, TxColor)
CTL := This.Attached[HWND]
If (BkColor <> "Trans")
If !This.CheckBkColor(BkColor, CTL.Classes[1])
Return False
If !This.CheckTxColor(TxColor)
Return False
If (BkColor <> CTL.BkColor) {
If (CTL.Brush) {
If (Ctl.Brush <> This.NullBrush)
DllCall("Gdi32.dll\DeleteObject", "Prt", CTL.Brush)
This.Attached[HWND].Brush := 0
}
If (BkColor = "Trans")
Brush := This.NullBrush
Else
Brush := DllCall("Gdi32.dll\CreateSolidBrush", "UInt", BkColor, "UPtr")
For I, V In CTL.Hwnds {
This.Attached[V].Brush := Brush
This.Attached[V].BkColor := BkColor
}
}
For I, V In Ctl.Hwnds
This.Attached[V].TxColor := TxColor
This.ErrorMsg := ""
DllCall("User32.dll\InvalidateRect", "Ptr", HWND, "Ptr", 0, "Int", 1)
Return True
}
Detach(HWND) {
This.ErrorMsg := ""
HWND += 0
If This.Attached.HasKey(HWND) {
CTL := This.Attached[HWND].Clone()
If (CTL.Brush) && (CTL.Brush <> This.NullBrush)
DllCall("Gdi32.dll\DeleteObject", "Prt", CTL.Brush)
For I, V In CTL.Classes {
If This.HandledMessages[V] > 0 {
This.HandledMessages[V] -= 1
If This.HandledMessages[V] = 0
OnMessage(This.WM_CTLCOLOR[V], "")
} }
For I, V In CTL.Hwnds
This.Attached.Remove(V, "")
DllCall("User32.dll\InvalidateRect", "Ptr", HWND, "Ptr", 0, "Int", 1)
CTL := ""
Return True
}
This.ErrorMsg := "Control " . HWND . " is not registered!"
Return False
}
Free() {
For K, V In This.Attached
If (V.Brush) && (V.Brush <> This.NullBrush)
DllCall("Gdi32.dll\DeleteObject", "Ptr", V.Brush)
For K, V In This.HandledMessages
If (V > 0) {
OnMessage(This.WM_CTLCOLOR[K], "")
This.HandledMessages[K] := 0
}
This.Attached := {}
Return True
}
IsAttached(HWND) {
Return This.Attached.HasKey(HWND)
}
}
classGuiColors_OnMessage(HDC, HWND) {
Critical
If classGuiColors.IsAttached(HWND) {
CTL := classGuiColors.Attached[HWND]
If (CTL.TxColor != "")
DllCall("Gdi32.dll\SetTextColor", "Ptr", HDC, "UInt", CTL.TxColor)
If (CTL.BkColor = "Trans")
DllCall("Gdi32.dll\SetBkMode", "Ptr", HDC, "UInt", 1)
Else
DllCall("Gdi32.dll\SetBkColor", "Ptr", HDC, "UInt", CTL.BkColor)
Return CTL.Brush
}
}
CreateGui()
Return