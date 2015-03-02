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
