//
//  NSDataGSCryptoAdditionsTests.m
//  GSCrypto
//

@import Foundation;
@import XCTest;

#import "NSDataGSCryptoAdditions.h"

@interface NSDataGSCryptoAdditionsTests : XCTestCase
@end

@implementation NSDataGSCryptoAdditionsTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)test_gs_HMACDigest {
    // SHA1
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gs_HMACDigestUsingAlgorithm:GSHMACAlgorithmSHA1 key:key];
        const void *bytes = "\xac\x20\x07\x1d\x3c\xb2\x62\x6f\xe2\xee\xb5\x9e\x75\xa7\xf8\xd0\x50\x69\x86\x20";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // MD5
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gs_HMACDigestUsingAlgorithm:GSHMACAlgorithmMD5 key:key];
        const void *bytes = "\x3f\xbd\xfb\x7c\x9d\x80\x71\xd9\x04\x81\x6c\x25\xfc\xaa\x8b\x94";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // SHA256
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gs_HMACDigestUsingAlgorithm:GSHMACAlgorithmSHA256 key:key];
        const void *bytes = "\xf8\xa6\x91\x70\x3d\x51\x56\x69\xc0\x3f\xe5\xc1\x65\x19\xc7\x9a\xc2\x7a\xd2\xe4\xdd\xdc\xba\xd6\xa8\x8f\x10\x15\xe2\xa7\x56\xf7";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // SHA384
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gs_HMACDigestUsingAlgorithm:GSHMACAlgorithmSHA384 key:key];
        const void *bytes = "\xe0\xb6\x0f\x66\x51\x2e\x3e\xb9\x31\x52\x6d\xba\x8e\xbf\x87\x62\x29\x64\x0f\x19\xf8\xe0\x7d\x94\x7a\x51\xe6\xa8\x36\xb2\x25\x7a\x51\x37\xcf\x6b\x9d\xd8\x6b\x93\x94\xc5\x4a\x26\x84\x50\x90\x68";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // SHA512
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gs_HMACDigestUsingAlgorithm:GSHMACAlgorithmSHA512 key:key];
        const void *bytes = "\xda\x67\xc9\x52\xe7\xfc\x57\x47\xa1\xe9\xc5\x14\x45\xd4\x56\xb4\x11\x5b\xce\x09\x0a\x0c\xe2\x22\x0c\x1b\x63\x4b\x8e\x92\x42\x48\x7b\xe7\x53\xdb\xf6\xd8\x31\x49\x1b\xfa\x03\x06\xdf\xaf\x60\x1c\xe7\x36\x27\x74\xca\xdb\xfd\x3f\x8e\x69\xee\xe5\x32\x31\x2e\x57";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // SHA224
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gs_HMACDigestUsingAlgorithm:GSHMACAlgorithmSHA224 key:key];
        const void *bytes = "\x84\x49\x57\x05\x52\x4e\x17\x38\xbf\xf2\x0d\x7b\x41\x9c\x98\x96\x1e\x89\x4d\xfa\x37\xf1\xd2\xe7\xd1\x49\x01\xb3";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
}

- (void)test_gs_crypto {
    // param error
    {
        NSError *error = nil;
        NSData *encryptedData = [[NSData data] gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmAES options:0 key:nil initializationVector:nil error:&error];
        XCTAssertNil(encryptedData);
        XCTAssertNotNil(error);
    }
    // AES128, ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = (GSCryptoOptionPKCS7Padding | GSCryptoOptionECBMode);
        NSData *key = [@"passwordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // AES128, CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = GSCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"passwordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // AES192, ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = (GSCryptoOptionPKCS7Padding | GSCryptoOptionECBMode);
        NSData *key = [@"passwordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // AES192, CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = GSCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"passwordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // AES256, ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = (GSCryptoOptionPKCS7Padding | GSCryptoOptionECBMode);
        NSData *key = [@"passwordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // AES256, CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = GSCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"passwordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // DES, ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = (GSCryptoOptionPKCS7Padding | GSCryptoOptionECBMode);
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmDES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmDES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // DES, CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = GSCryptoOptionPKCS7Padding;
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmDES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmDES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // 3DES, ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = (GSCryptoOptionPKCS7Padding | GSCryptoOptionECBMode);
        NSData *key = [@"passwordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithm3DES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithm3DES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // 3DES, CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = GSCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithm3DES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithm3DES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // CAST (MIN), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = (GSCryptoOptionPKCS7Padding | GSCryptoOptionECBMode);
        NSData *key = [@"passw" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // CAST (MIN), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = GSCryptoOptionPKCS7Padding;
        NSData *key = [@"passw" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // CAST (MAX), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = (GSCryptoOptionPKCS7Padding | GSCryptoOptionECBMode);
        NSData *key = [@"passwordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // CAST (MAX), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = GSCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC4 (MIN), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = (GSCryptoOptionPKCS7Padding | GSCryptoOptionECBMode);
        NSData *key = [@"p" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC4 (MIN), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = GSCryptoOptionPKCS7Padding;
        NSData *key = [@"p" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC4 (MAX), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = (GSCryptoOptionPKCS7Padding | GSCryptoOptionECBMode);
        NSData *key = [@"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC4 (MAX), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = GSCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC2 (MIN), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = (GSCryptoOptionPKCS7Padding | GSCryptoOptionECBMode);
        NSData *key = [@"p" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC2 (MIN), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = GSCryptoOptionPKCS7Padding;
        NSData *key = [@"p" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC2 (MAX), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = (GSCryptoOptionPKCS7Padding | GSCryptoOptionECBMode);
        NSData *key = [@"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC2 (MAX), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = GSCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // Blowfish (MIN), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = (GSCryptoOptionPKCS7Padding | GSCryptoOptionECBMode);
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // Blowfish (MIN), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = GSCryptoOptionPKCS7Padding;
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // Blowfish (MAX), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = (GSCryptoOptionPKCS7Padding | GSCryptoOptionECBMode);
        NSData *key = [@"passwordpasswordpasswordpasswordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // Blowfish (MAX), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSCryptoOptions options = GSCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpasswordpasswordpasswordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gs_encryptedDataUsingAlgorithm:GSCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gs_decryptedDataUsingAlgorithm:GSCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
}

@end
