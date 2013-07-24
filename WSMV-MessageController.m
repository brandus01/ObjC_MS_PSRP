//
//  WSMV-MessageController.m
//  powershell
//
//  Created by Joshua Langford on 8/22/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import "WSMV-MessageController.h"
#import "CoreFoundation/CoreFoundation.h"
#import "WSMV-Shell.h"
#import "PSRP_RunSpacePool.h"
#import "MS-WSMV.h"
#import "MS-PSRP.h"
#import "Server.h"
#import "Credential.h"
#import "GDataXMLNode.h"
#import "NSData+Base64.h"
#import "NSString+Base64.h"

//#import <GSS/gssapi.h>
//#import <GSS/gssapi_krb5.h>

#import "MS-NLMP.h"
//#include "test_ntlm.h"


@interface WSMV_MessageController()

@property (nonatomic,copy) NSString *terminateMessageID;
@property (nonatomic,copy) NSMutableString *decodedOutput;
@end

@implementation WSMV_MessageController

@synthesize delegate;
//@synthesize ServerName;
//@synthesize Port;
//@synthesize UserName;
//@synthesize Password;
@synthesize CurrentServer;
@synthesize ResourcePath;
@synthesize To;
@synthesize Script;

@synthesize ms_wsmv;
@synthesize ms_psrp;
@synthesize ms_nlmp;
@synthesize Shell;
@synthesize RunSpacePool;

@synthesize terminateMessageID; //keep track of terminate messages so we can ignore faults from it
@synthesize decodedOutput; //used for appending responses that come in multiple fragments
@synthesize pendingData;  //holding area for data we want to post, but need to reauthorize first

@synthesize authNegotiate; //BOOL to determine authentication mode
@synthesize unAuthCount; //to make sure we don't retry failed credentials

#pragma mark ntlm
#include "ntlm.h"
#include "ntlm_compute.h"
#include "ntlm_message.h"
#include "sspi.h"

#define boundary @"--Encrypted Boundary\r\n"
#define packageName "NTLM"

SecurityFunctionTable* table;
CtxtHandle context;
uint32 fContextReq;
SECURITY_STATUS status;
CredHandle credentials;
SecPkgInfo* pPackageInfo;
uint32 cbMaxLen;

-(void)ntlm_negotiate{
    NSLog(@"ntlm_negotiate");
    
    void* output_buffer;
    SecBuffer output_SecBuffer;
    SecBufferDesc output_SecBuffer_desc;
    SecBuffer* p_SecBuffer;
    TimeStamp expiration;
    uint32 pfContextAttr;
    fContextReq = ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_DELEGATE;
    
    output_buffer = xmalloc(cbMaxLen);
    
  output_SecBuffer_desc.ulVersion = 0;
	output_SecBuffer_desc.cBuffers = 1;
	output_SecBuffer_desc.pBuffers = &output_SecBuffer;
    
	output_SecBuffer.cbBuffer = cbMaxLen;
	output_SecBuffer.BufferType = SECBUFFER_TOKEN;
	output_SecBuffer.pvBuffer = output_buffer;
    
    status = table->InitializeSecurityContext(&credentials, NULL, NULL, fContextReq, 0, 0, NULL, 0,
                                              &context, &output_SecBuffer_desc, &pfContextAttr, &expiration);
    
    if (status != SEC_I_CONTINUE_NEEDED)
	{
		printf("InitializeSecurityContext status: 0x%08X\n", status);
	}
    
    p_SecBuffer = &output_SecBuffer_desc.pBuffers[0];
    
	//printf("BufferType: 0x%04X cbBuffer:%d\n", p_SecBuffer->BufferType, p_SecBuffer->cbBuffer);
    
	//freerdp_hexdump((uint8*) p_SecBuffer->pvBuffer, p_SecBuffer->cbBuffer);
    
	table->FreeCredentialsHandle(&credentials);
    
	FreeContextBuffer(pPackageInfo);
    
    NSData *msg_Negotiate=[NSData dataWithBytes:p_SecBuffer->pvBuffer length:p_SecBuffer->cbBuffer];
    
    NSLog(@"msg_Negotiate: %@",[msg_Negotiate description]);
    
    NSString *negString=[NSString stringWithFormat:@"Negotiate %@",[msg_Negotiate base64EncodedString]];
    
    NSDictionary *Headers=[NSDictionary dictionaryWithObjectsAndKeys:
                           @"application/soap+xml;charset=UTF-8",@"Content-Type",
                           @"Keep-Alive",@"Connection",
                           @"Microsoft WinRM Client",@"User-Agent",
                           negString,@"Authorization",
                           nil];
    
    RKRequest * request = [[RKClient sharedClient] requestWithResourcePath:ResourcePath];
    [request setDelegate:self];
    [request setMethod:RKRequestMethodPOST];
    [request setAdditionalHTTPHeaders:Headers];
    
    //send is asynchronous, therefore this message controller must be retained so that it is not deallocated before reskit responds
    [delegate showStatus:@"Sending"];
    [request send];
    
}

-(NSMutableData*)encryptMessage:(NSData*)message{
    
    NSLog(@"originalLength %d",[message length]);
    
    SecBuffer EncryptBuffers[2];
    EncryptBuffers[0].BufferType = SECBUFFER_DATA; // Message
    EncryptBuffers[0].cbBuffer = [message length];
    EncryptBuffers[0].pvBuffer = xmalloc(EncryptBuffers[0].cbBuffer);
    memcpy(EncryptBuffers[0].pvBuffer, [message bytes], EncryptBuffers[0].cbBuffer);
    
    //EncryptBuffers[1]=*output_SecBuffer_desc.pBuffers;
    //I think we can send an empty buffer to the encryption
    EncryptBuffers[1].BufferType = SECBUFFER_TOKEN; // Signature
    EncryptBuffers[1].cbBuffer = 16;
    EncryptBuffers[1].pvBuffer = xmalloc(EncryptBuffers[1].cbBuffer);
    
    SecBufferDesc Message;
    
    Message.cBuffers = 2;
    Message.ulVersion = SECBUFFER_VERSION;
    Message.pBuffers = (PSecBuffer) &EncryptBuffers;
    
    NTLM_CONTEXT *ntlm=sspi_SecureHandleGetLowerPointer(&context);
    
    table->EncryptMessage(&context,0,&Message,ntlm->SendSeqNum);
    
    NSMutableData *encryptedMessage=[NSMutableData data];
    uint8 length[4] = "\x10\x00\x00\x00"; //16
    
    [encryptedMessage appendBytes:&length length:sizeof(length)]; //length of signature
    [encryptedMessage appendBytes:EncryptBuffers[1].pvBuffer length:16]; //signature
    [encryptedMessage appendBytes:EncryptBuffers[0].pvBuffer length:EncryptBuffers[0].cbBuffer]; //data
    
    NSLog(@"encryptedMessageLength: %d",[encryptedMessage length]);
    
    NSMutableData *body=[NSMutableData data];
    
    [body appendData:[[NSString stringWithFormat:@"%@Content-Type: application/HTTP-SPNEGO-session-encrypted\r\n",boundary] dataUsingEncoding:NSUTF8StringEncoding]];
    [body appendData:[[NSString stringWithFormat:@"OriginalContent: type=application/soap+xml;charset=UTF-8;Length=%d\r\n%@",[message length],boundary] dataUsingEncoding:NSUTF8StringEncoding]];
    [body appendData:[[NSString stringWithFormat:@"Content-Type: application/octet-stream\r\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    
    [body appendData:encryptedMessage];
    
    [body appendData:[[NSString stringWithFormat:@"%@",boundary] dataUsingEncoding:NSUTF8StringEncoding]];
    
    NSLog(@"encrypted bodyLength: %d",[body length]);
    
    return body;
}

-(NSData*)decryptMessage:(NSData*)responseData{
    
    //accepted message
    NTLM_CONTEXT *ntlm=sspi_SecureHandleGetLowerPointer(&context);
    
        if(ntlm->state == NTLM_STATE_INITIAL){
            printf("NTLM_STATE_INITIAL\n");
        }
        else if(ntlm->state == NTLM_STATE_NEGOTIATE){
            printf("NTLM_STATE_NEGOTIATE\n");
        }
        else if(ntlm->state == NTLM_STATE_CHALLENGE){
            printf("NTLM_STATE_CHALLENGE\n");
        }
        else if(ntlm->state == NTLM_STATE_AUTHENTICATE){
            printf("NTLM_STATE_AUTHENTICATE\n");
        }
        else if(ntlm->state == NTLM_STATE_FINAL){
            printf("NTLM_STATE_FINAL\n");
        }
    
    if(ntlm->state==NTLM_STATE_FINAL){
        //we should be authenticated and receiving messages at this point
        NSLog(@"NTLM_STATE_FINAL");
        
        NSData *headerAsData=[@"Content-Type: application/octet-stream\r\n" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *boundaryAsData=[boundary dataUsingEncoding:NSUTF8StringEncoding];
        //NSLog(@"headerAsData: %@",headerAsData);
        //NSLog(@"boundaryAsData: %@",boundaryAsData);
        
        NSData *body=responseData;
        
        //NSLog(@"responseasData: %@",[body description]);
        
        NSRange range=[body rangeOfData:headerAsData options:1 range:NSMakeRange(0, [body length])];
        
        if(range.location != NSNotFound){
            //NSLog(@"found beginning at location %d",range.location);
            
            //get the data between the 2nd and 3rd boundaries
            int start=range.location+range.length;
            int length=[body length]-start-[boundaryAsData length];
            
            NSData *encryptedBody=[body subdataWithRange:NSMakeRange(start, length)];
            
            NSLog(@"encrypted body: %@",[encryptedBody description]);
            
            uint32 sigLength = 0;
            NSData *sigLengthData=[encryptedBody subdataWithRange:NSMakeRange(0, 4)];
            //NSLog(@"sigLength: %@",[sigLengthData description]);
            sigLength=*(const uint32 *)[sigLengthData bytes];
            //NSLog(@"sigLength: %d",sigLength);
            
            NSData *sigData=[encryptedBody subdataWithRange:NSMakeRange(4, sigLength)];
            NSLog(@"sigData: %@",[sigData description]);
            void *signature=xmalloc([sigData length]);
            memcpy(signature, [sigData bytes], [sigData length]);
            //freerdp_hexdump(*signature, sizeof(signature));
            
            
            NSData *msgData=[encryptedBody subdataWithRange:NSMakeRange(4+sigLength, [encryptedBody length]-4-sigLength)];
            NSLog(@"msgData: %@",[msgData description]);
            void *encryptedMessage = xmalloc([msgData length]);
            memcpy(encryptedMessage, [msgData bytes], [msgData length]);
            NSLog(@"encryptedMessage: %s",encryptedMessage);
            
            //sspi
            SecBuffer EncryptBuffers[2];
            EncryptBuffers[0].BufferType = SECBUFFER_DATA; // Message
            //EncryptBuffers[0].cbBuffer = sizeof(encryptedMessage);
            EncryptBuffers[0].cbBuffer = [msgData length];
            EncryptBuffers[0].pvBuffer = xmalloc(EncryptBuffers[0].cbBuffer);
            memcpy(EncryptBuffers[0].pvBuffer, encryptedMessage, EncryptBuffers[0].cbBuffer);
            
            //EncryptBuffers[1].BufferType = SECBUFFER_TOKEN; // Signature
            EncryptBuffers[1].BufferType = SECBUFFER_TOKEN;
            EncryptBuffers[1].cbBuffer = sigLength;
            EncryptBuffers[1].pvBuffer = xmalloc(EncryptBuffers[1].cbBuffer);
            memcpy(EncryptBuffers[1].pvBuffer, signature, EncryptBuffers[1].cbBuffer);

            SecBufferDesc Message;
            
            Message.cBuffers = 2;
            Message.ulVersion = SECBUFFER_VERSION;
            Message.pBuffers = (PSecBuffer) &EncryptBuffers;
            
            table->DecryptMessage(&context,&Message,ntlm->RecvSeqNum,0);
            
            NSData *decryptedData=[NSData dataWithBytes:EncryptBuffers[0].pvBuffer length:EncryptBuffers[0].cbBuffer];
            
            NSLog(@"decryptedData: %@",decryptedData);
            
            NSString *decryptedMessage=[[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
            NSLog(@"decryptedMessage: %@",decryptedMessage);
            
            return decryptedData;
            
            
        }
    }
    
    return nil;
}

-(void)ntlm_authenticateWithResponseHeaders:(NSDictionary*)headers{
    NSLog(@"ntlm_authenticate");
    
    NSString *authenticate = [headers valueForKey:@"Www-Authenticate"];
    
    NSRange range=[authenticate rangeOfString:@"Negotiate "];
    if(range.location==NSNotFound){
        return;
    }
    
    NSString *challengeString=[authenticate substringFromIndex:range.length];
    NSData *msg_Challenge=[NSData dataWithBase64EncodedString:challengeString];
    
    NSLog(@"challenge: %@",msg_Challenge);
    
    NSData *messageTypeData=[msg_Challenge subdataWithRange:NSMakeRange(8, 4)];
    uint32_t messageType=*(const UInt8 *)[messageTypeData bytes];
    
    if(messageType==2){
        
        void* output_buffer;
        SecBuffer output_SecBuffer;
        SecBufferDesc output_SecBuffer_desc;
        uint32 pfContextAttr;
        TimeStamp expiration;
        SecBuffer* p_SecBuffer;
        
        output_buffer = xmalloc(cbMaxLen);
        
        output_SecBuffer_desc.ulVersion = 0;
        output_SecBuffer_desc.cBuffers = 1;
        output_SecBuffer_desc.pBuffers = &output_SecBuffer;
        
        output_SecBuffer.cbBuffer = cbMaxLen;
        output_SecBuffer.BufferType = SECBUFFER_TOKEN;
        output_SecBuffer.pvBuffer = output_buffer;
        
        Byte *response = (Byte*)malloc([msg_Challenge length]);
        memcpy(response, [msg_Challenge bytes], [msg_Challenge length]);
        
        SecBuffer input_SecBuffer;
        SecBufferDesc input_SecBuffer_desc;
        
        input_SecBuffer_desc.ulVersion = 0;
        input_SecBuffer_desc.cBuffers = 1;
        input_SecBuffer_desc.pBuffers = &input_SecBuffer;
        
        input_SecBuffer.cbBuffer = cbMaxLen;
        input_SecBuffer.BufferType = SECBUFFER_TOKEN;
        input_SecBuffer.pvBuffer = response;
        
        //move context from Challenge to Authenticate, and calculate all the keys 
        status = table->InitializeSecurityContext(&credentials, &context, NULL, fContextReq, 0, 0, &input_SecBuffer_desc, 0,
                                                  &context, &output_SecBuffer_desc, &pfContextAttr, &expiration);
        
        p_SecBuffer = &output_SecBuffer_desc.pBuffers[0];
        
        NSData *msg_Authenticate=[NSData dataWithBytes:p_SecBuffer->pvBuffer length:p_SecBuffer->cbBuffer];
        
        NSString *authString=[NSString stringWithFormat:@"Negotiate %@",[msg_Authenticate base64EncodedString]];
        
        NSData *body=[self encryptMessage:pendingData];
        pendingData=nil;
        
        //NTLM Headers
        NSString *bodyLength=[NSString stringWithFormat:@"%d",[body length]];
        NSLog(@"auth bodyLength %@",bodyLength);
        
        NSDictionary *Headers=[NSDictionary dictionaryWithObjectsAndKeys:
                               @"multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"",@"Content-Type",
                               @"Keep-Alive",@"Connection",
                               @"Microsoft WinRM Client",@"User-Agent",
                               bodyLength,@"Content-Length",
                               authString,@"Authorization",
                               nil];
        
        
        RKRequest * request = [[RKClient sharedClient] requestWithResourcePath:ResourcePath];
        [request setDelegate:self];
        [request setMethod:RKRequestMethodPOST];
        [request setAdditionalHTTPHeaders:Headers];
        [request setHTTPBody:body];
        
        //send is asynchronous, therefore this message controller must be retained so that it is not deallocated before reskit responds
        [delegate showStatus:@"Sending"];
        [request send];
        
    }//end authentication response
}

-(void)initSSPIContext{
    //set the credentials
    SEC_WINNT_AUTH_IDENTITY identity;
    TimeStamp expiration;
    
    table = InitSecurityInterface();
    
    //package didn't work when we tried to get it out of sspi.c so we pasted it here
    SecPkgInfoA NTLM_SecPkgInfoA =
    {
        0x00082B37, /* fCapabilities */
        1, /* wVersion */
        0x000A, /* wRPCID */
        0x00000B48, /* cbMaxToken */
        "NTLM", /* Name */
        "NTLM Security Package" /* Comment */
    };
    
    pPackageInfo=&NTLM_SecPkgInfoA;
    
    cbMaxLen = pPackageInfo->cbMaxToken;
    
    //identity.User = (uint16*) xstrdup("test");
    //identity.UserLength = sizeof("test");
    //identity.Domain = (uint16*) NULL;
    //identity.DomainLength = 0;
    //identity.Password = (uint16*) xstrdup("test");
    //identity.PasswordLength = sizeof("test");
    
    const char *cUser=[CurrentServer.defaultCredential.userName cStringUsingEncoding:NSUTF8StringEncoding];
    
    identity.User = (uint16*) xstrdup(cUser);
    identity.UserLength = sizeof(cUser);
    
    if([CurrentServer.defaultCredential.domain length]){
        const char *cDomain=[CurrentServer.defaultCredential.domain cStringUsingEncoding:NSUTF8StringEncoding];
        identity.Domain = (uint16*) xstrdup(cDomain);
        identity.DomainLength = sizeof(cDomain);
    }
    else{
        identity.Domain = (uint16*) NULL;
        identity.DomainLength = 0;
    }
    
    const char *cPassword=[CurrentServer.defaultCredential.password cStringUsingEncoding:NSUTF8StringEncoding];
    identity.Password = (uint16*) xstrdup(cPassword);
    identity.PasswordLength = sizeof(cPassword);
    
    identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
    
    status = table->AcquireCredentialsHandle(NULL, packageName, SECPKG_CRED_OUTBOUND, NULL, &identity, NULL, NULL, &credentials, &expiration);
    
    if (status != SEC_E_OK)
    {
        printf("AcquireCredentialsHandle status: 0x%08X\n", status);
    }
}

#pragma mark send

-(void)setServer: (Server*)server{
    CurrentServer=server;
    unAuthCount=0;
    
    ResourcePath=[NSString stringWithFormat:@"wsman?PSVersion=%d.0",[server.psVersion intValue]];
    To=[NSString stringWithFormat:@"http://%@:%@/%@",server.name,server.port,ResourcePath];
    
    //set up RestClient
    RKObjectManager* objectManager = [RKObjectManager objectManagerWithBaseURLString:[NSString stringWithFormat:@"http://%@:%@",server.name,server.port]];
    [[RKClient sharedClient] setBaseURL:objectManager.baseURL];
    [[RKClient sharedClient] setTimeoutInterval:30];
    
    NSLog(@"authentication type: %@",CurrentServer.authentication);
    
    if([CurrentServer.authentication isEqualToString:@"Basic"]){
        authNegotiate=FALSE;
        [[RKClient sharedClient] setUsername:server.defaultCredential.userName];
        [[RKClient sharedClient] setPassword:server.defaultCredential.password];
        [[RKClient sharedClient] setAuthenticationType:RKRequestAuthenticationTypeHTTPBasic];
    }
    else if([CurrentServer.authentication isEqualToString:@"Negotiate"]){
        
        authNegotiate=TRUE;
        
        [self initSSPIContext];
        
    }//end negotiate
    
}

-(id)init{
    
    if(self==[super init]){
        [delegate showStatus:@"Waiting"];
        
        ms_wsmv=[[MS_WSMV alloc] init];
        ms_psrp=[[MS_PSRP alloc] init];

    }//end init
    
    return self;
}

-(void)getWSMAN{
    NSLog(@"getWSMAN");
    
    RKRequest * request = [[RKClient sharedClient] requestWithResourcePath:ResourcePath];
    [request setDelegate:self];
    [request setMethod:RKRequestMethodGET];

    NSLog(@"requesT: %@",[request URL]);
    
    [request send];
}


-(void)createShell{
    //PSRP
    Shell=[[WSMV_Shell alloc] init];
    RunSpacePool=[[PSRP_RunSpacePool alloc] initWithRPID:[self generateUUID] PID:[self generateUUID]];
    NSString *creationXml=[[ms_psrp xml_NewShellWithRPID:RunSpacePool.RPID] base64EncodedString];
    
    //Create Request
    //MS-PSRP 3.1.5.3.1 Rules for the wxf:Create Message
    GDataXMLElement *createEnvelope=[ms_wsmv xmlEnvelope];
    NSString *createMessageId=[self generateUUID];
    GDataXMLElement *createHeader=[ms_wsmv xmlEnvelopeCreateHeaderTo:To MessageID:createMessageId];
    [createEnvelope addChild:createHeader];
    GDataXMLElement *createBody=[ms_wsmv xmlEnvelopeCreateBodyWithCreationXML:creationXml];
    [createEnvelope addChild:createBody];
    
    NSData *createData=[createEnvelope.XMLString dataUsingEncoding:NSUTF8StringEncoding];
    
    if(authNegotiate){
        NSLog(@"Negotiate");
        
        //we aren't ready to send until we are authenticated, hold it for a bit
        pendingData=createData;
        
        [self ntlm_negotiate];
        
        return;
    }
    
    [self SendRequestWithHTTPBody:createData];
}

-(NSString*)command:(NSString*)script{
    Script=script;
    
    //Command Envelope
    //MS-PSRP 3.1.5.3.3 Rules for the wxf:Command Message
    GDataXMLElement *commandEnvelope=[ms_wsmv xmlEnvelope];
    NSString *commandMessageId=[self generateUUID];
    GDataXMLElement *commandHeader=[ms_wsmv xmlEnvelopeCommandHeaderTo:To MessageID:commandMessageId ShellID:Shell.ShellID];
    [commandEnvelope addChild:commandHeader];
    
    NSLog(@"command: %@",Script);
    NSData *commandArgs=[ms_psrp xml_CREATE_PIPELINEwithRPID:RunSpacePool.RPID PID:RunSpacePool.PID UnicodeScript:Script];
    
    GDataXMLElement *commandBody=[ms_wsmv xmlEnvelopeCommandBodyWithArgs:[commandArgs base64EncodedString]];
    [commandEnvelope addChild:commandBody];
    
    NSData *commandData=[commandEnvelope.XMLString dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"command: %@",commandMessageId);
    //testing
    //NSLog(@"envelope: %@",commandEnvelope.XMLString);
    [self SendRequestWithHTTPBody:commandData];
    return commandMessageId;
}

-(void)receive{
    //Receive Envelope
    //MS-PSRP 3.1.5.3.7 Rules for the wxf:Receive Message
    GDataXMLElement *receiveEnvelope=[ms_wsmv xmlEnvelope];
    NSString *receiveMessageId=[self generateUUID];
    GDataXMLElement *receiveHeader=[ms_wsmv xmlEnvelopeReceiveHeaderTo:To MessageID:receiveMessageId ShellID:Shell.ShellID CommandId:nil];
    [receiveEnvelope addChild:receiveHeader];
    GDataXMLElement *receieveBody=[ms_wsmv xmlEnvelopeReceiveBodyForCommandId:Shell.CommandId];
    [receiveEnvelope addChild:receieveBody];
    
    NSData *receiveData=[receiveEnvelope.XMLString dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"receive %@",receiveMessageId);
    //NSLog(@"receive %@",receiveEnvelope.XMLString);
    [self SendRequestWithHTTPBody:receiveData];
}

-(void)send:(NSMutableDictionary*)inputdict{
    
    NSString *input=[inputdict valueForKey:@"Input"];
    NSString *key=[inputdict valueForKey:@"Key"];
    
    NSString *inputXml=[[ms_psrp xml_PIPELINE_HOST_RESPONSEwithRPID:RunSpacePool.RPID PID:RunSpacePool.PID Key:key Value:input] base64EncodedString];
    
    //Send Request
    //MS-PSRP 3.1.5.3.5 Rules for the wxf:Send Message
    GDataXMLElement *inputEnvelope=[ms_wsmv xmlEnvelope];
    NSString *inputMessageId=[self generateUUID];
    GDataXMLElement *inputHeader=[ms_wsmv xmlEnvelopeSendHeaderTo:To MessageID:inputMessageId ShellID:Shell.ShellID CommandId:Shell.CommandId];
    [inputEnvelope addChild:inputHeader];
    GDataXMLElement *inputBody=[ms_wsmv xmlEnvelopeSendBodyForCommandId:Shell.CommandId Args:inputXml];
    [inputEnvelope addChild:inputBody];
    
    NSData *sendData=[inputEnvelope.XMLString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSLog(@"sending %@",inputMessageId);
    
    [delegate showStatus:@"Sending"];
    [self SendRequestWithHTTPBody:sendData];
}

-(void)signal{
    //Signal Envelope
    //MS-PSRP 3.1.5.3.9 Rules for the wxf:Signal Message
    GDataXMLElement *signalEnvelope=[ms_wsmv xmlEnvelope];
    terminateMessageID=[self generateUUID];
    GDataXMLElement *signalHeader=[ms_wsmv xmlEnvelopeSignalHeaderTo:To MessageID:terminateMessageID ShellID:Shell.ShellID CommandId:Shell.CommandId];
    [signalEnvelope addChild:signalHeader];
    
    GDataXMLElement *signalBody=[ms_wsmv xmlEnvelopeSignalBodyForCommandId:Shell.CommandId];
    [signalEnvelope addChild:signalBody];
    
    NSData *signalData=[signalEnvelope.XMLString dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"signal messageid: %@",terminateMessageID);
    NSLog(@"Terminating Command %@",Shell.CommandId);
    [self SendRequestWithHTTPBody:signalData];
}

-(void)deleteShell{
    //Delete Envelope
    //MS-PSRP 3.1.5.3.11 Rules for the wxf:Delete Message
    GDataXMLElement *deleteEnvelope=[ms_wsmv xmlEnvelope];
    NSString *deleteMessageId=[self generateUUID];
    GDataXMLElement *deleteHeader=[ms_wsmv xmlEnvelopeDeleteHeaderTo:To MessageID:deleteMessageId ShellID:Shell.ShellID];
    [deleteEnvelope addChild:deleteHeader];
    
    GDataXMLElement *deleteBody=[ms_wsmv xmlEnvelopeDeleteBody];
    [deleteEnvelope addChild:deleteBody];
    
    NSData *deleteData=[deleteEnvelope.XMLString dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"Delete Shell %@",deleteMessageId);
    [self SendRequestWithHTTPBody:deleteData];
}

#pragma mark - WSMV responses

-(void)createResponse: (GDataXMLDocument*)envelope{
    
    NSArray *results=[envelope nodesForXPath:@"//w:Selector[@Name='ShellId']" error:nil];
    
    if([results count]>0){
        GDataXMLNode *shellxml = [results objectAtIndex:0];
        Shell.ShellID=shellxml.stringValue;
        NSLog(@"ShellId %@",Shell.ShellID);
        
        //Receive Envelope
        //MS-PSRP 3.1.5.3.7 Rules for the wxf:Receive Message
        GDataXMLElement *receiveEnvelope=[ms_wsmv xmlEnvelope];
        NSString *receiveMessageId=[self generateUUID];
        GDataXMLElement *receiveHeader=[ms_wsmv xmlEnvelopeReceiveHeaderTo:To MessageID:receiveMessageId ShellID:Shell.ShellID CommandId:nil];
        [receiveEnvelope addChild:receiveHeader];
        GDataXMLElement *receieveBody=[ms_wsmv xmlEnvelopeReceiveBodyForCommandId:nil];
        [receiveEnvelope addChild:receieveBody];
        
        NSData *receiveData=[receiveEnvelope.XMLString dataUsingEncoding:NSUTF8StringEncoding];
        [self SendRequestWithHTTPBody:receiveData];
        [delegate showStatus:@"Connected"];
    }
}

-(void)receiveResponse: (GDataXMLDocument*)envelope{
    [delegate showStatus:@"Receiving"];
    decodedOutput=nil;
    
    
    GDataXMLNode *relatesToXml=[[envelope nodesForXPath:@"//a:RelatesTo" error:nil] lastObject];
    NSString *relatesToID=relatesToXml.stringValue;
    NSLog(@"relates to %@",relatesToID);
    
    NSArray *results=[envelope nodesForXPath:@"//rsp:Stream[@Name='stdout']" error:nil];
    
    for(int i=0;i<[results count];i++){
        
        NSString *string=[(GDataXMLNode*)[results objectAtIndex:i] stringValue];
        //NSData *data=[NSData dataFromBase64String:string];
        //NSData *data=[NSData dataFromBase64String:string];
        NSData *data=[NSData dataWithBase64EncodedString:string];
        NSData *header=[data subdataWithRange:NSMakeRange(0, 64)];
        NSData *fragmentSequence=[data subdataWithRange:NSMakeRange(16, 1)];
        uint32_t fragment=*(const UInt8 *)[fragmentSequence bytes];
        NSData *messageType;
        uint32_t type;
        NSData *body;
        
        //NSLog(@"header: %@",[header description]);
        NSLog(@"fragmentSequence: %d",fragment);
        
        if(fragment==ms_psrp.fragment_Start || fragment==ms_psrp.fragment_StartAndEnd){
            NSLog(@"fragment_Start");
            
            messageType=[header subdataWithRange:NSMakeRange(25, 4)];
            NSLog(@"messageType %@",[messageType description]);
            type=*(const UInt32 *)[messageType bytes];
            
            body=[data subdataWithRange:NSMakeRange(64, data.length-64)];
            decodedOutput=[[NSMutableString alloc] initWithData:body encoding:NSUTF8StringEncoding];
            
            if(fragment!=ms_psrp.fragment_StartAndEnd){
                continue;
            }
        }
        else if(fragment==ms_psrp.fragment_Middle){
            NSLog(@"fragment_Middle");
            body=[data subdataWithRange:NSMakeRange(21, data.length-21)];
            
            NSString *more=[[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
            [decodedOutput appendString:more];
            continue;
        }
        else if(fragment==ms_psrp.fragment_End){
            NSLog(@"fragment_End");
            body=[data subdataWithRange:NSMakeRange(21, data.length-21)];
            
            NSString *more=[[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
            [decodedOutput appendString:more];
        }
        
        //NSLog(@"Decodedoutput %@",decodedOutput);
        
        //NSString *decoded= [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        
        if(type==ms_psrp.msgType_SESSION_CAPABILITY){
            NSLog(@"SESSION_CAPABILITY Response");
            
            //Receive Envelope
            //MS-PSRP 3.1.5.3.7 Rules for the wxf:Receive Message
            GDataXMLElement *receiveEnvelope=[ms_wsmv xmlEnvelope];
            NSString *receiveMessageId=[self generateUUID];
            GDataXMLElement *receiveHeader=[ms_wsmv xmlEnvelopeReceiveHeaderTo:To MessageID:receiveMessageId ShellID:Shell.ShellID CommandId:nil];
            [receiveEnvelope addChild:receiveHeader];
            GDataXMLElement *receieveBody=[ms_wsmv xmlEnvelopeReceiveBodyForCommandId:nil];
            [receiveEnvelope addChild:receieveBody];
            
            NSData *receiveData=[receiveEnvelope.XMLString dataUsingEncoding:NSUTF8StringEncoding];
            [self SendRequestWithHTTPBody:receiveData];
        }
        
        if(type==ms_psrp.msgType_INIT_RUNSPACEPOOL){
            NSLog(@"INIT_RUNSPACEPOOL Response");
            
        }
        
        if(type==ms_psrp.msgType_APPLICATION_PRIVATE_DATA){
            NSLog(@"APPLICATION_PRIVATE_DATA Response");
            
            NSLog(@"%@",decodedOutput);
            
            /*
            GDataXMLElement *appXML=[[GDataXMLElement alloc] initWithXMLString:decodedOutput error:nil];
            
            NSArray *results=[appXML nodesForXPath:@"//En[S='CLRVersion']/Version" error:nil];
            
            if([results count]>0){
                GDataXMLNode *versionXML = [results lastObject];
                NSString *versionString=[versionXML stringValue];
                NSLog(@"version: %@",versionString);
                
                CurrentServer.clrVersion=versionString;
                
                id appDelegate = (id)[[UIApplication sharedApplication] delegate];
                NSManagedObjectContext *mcontext = [appDelegate managedObjectContext];
                
                NSError *error = nil;
                if (mcontext != nil)
                {
                    if ([mcontext hasChanges] && ![mcontext save:&error])
                    {
                        NSLog(@"CLRVersion error %@, %@", error, [error userInfo]);
                    }
                }
            }
            */
            
            return;
        }
        
        if(type==ms_psrp.msgType_RUNSPACEPOOL_STATE){
            NSLog(@"RUNSPACEPOOL_STATE Response");
            GDataXMLDocument *decodedXML=[[GDataXMLDocument alloc] initWithXMLString:decodedOutput options:0 error:nil];
            NSArray *results=[decodedXML nodesForXPath:@"//I32[@N='RunspaceState']" error:nil];
            
            if([results count]>0){
                GDataXMLNode *runSpaceStateXML=[results objectAtIndex:0];
                RunSpacePool.RunspacePoolState=[runSpaceStateXML.stringValue intValue];
                NSLog(@"runspacepoolstate: %d",RunSpacePool.RunspacePoolState);
            }
            
            if(i==[results count]-1 && RunSpacePool.RunspacePoolState==ms_psrp.RunspacePoolState_Opened && Shell.CommandId==nil){
                NSLog(@"Should Send Command Next");
                
                //let delegate know shell is open
                [delegate showStatus:@"Connected"];
                [delegate shellCreated];
            }
            
            return;
        }// End of RunSpacePool State
        
        if(type==ms_psrp.msgType_PIPELINE_HOST_CALL){
            NSLog(@"PIPELINE_HOST_CALL Response");
            
            GDataXMLDocument *object=[[GDataXMLDocument alloc] initWithXMLString:decodedOutput options:0 error:nil];
            
            NSMutableDictionary *outputDict=[ms_psrp parseOutputForObject:object];
            [delegate showOutput:outputDict];
            [delegate showStatus:@"Input Required"];
        }
        
        if(type==ms_psrp.msgType_PIPELINE_OUTPUT){
            NSLog(@"PIPELINE_OUTPUT Response");
            //NSLog(@"Decoded %@",decodedOutput);
            
            GDataXMLDocument *object=[[GDataXMLDocument alloc] initWithXMLString:decodedOutput options:0 error:nil];
            
            NSMutableDictionary *outputDict=[ms_psrp parseOutputForObject:object];
            [delegate showOutput:outputDict];
        }
        
        if(type==ms_psrp.msgType_ERROR_RECORD){
            NSLog(@"ERROR_RECORD Response");
            NSLog(@"stdout: %@",decodedOutput);
            
            GDataXMLDocument *object=[[GDataXMLDocument alloc] initWithXMLString:decodedOutput options:0 error:nil];
            
            NSMutableDictionary *outputDict=[ms_psrp parseOutputForObject:object];
            [delegate showOutput:outputDict];
            
            [delegate showStatus:@"Disconnected"];
        }
        
        if(type==ms_psrp.msgType_PIPELINE_STATE){
            NSLog(@"PIPELINE_STATE Response");
            GDataXMLDocument *decodedXML=[[GDataXMLDocument alloc] initWithXMLString:decodedOutput options:0 error:nil];
            NSArray *results=[decodedXML nodesForXPath:@"//I32[@N='PipelineState']" error:nil];
            
            if([results count]>0){
                GDataXMLNode *pipelineStateXML=[results objectAtIndex:0];
                RunSpacePool.PipelineState=[pipelineStateXML.stringValue intValue];
                NSLog(@"PipelineState: %d",RunSpacePool.PipelineState);
            }
            
            if(RunSpacePool.PipelineState==ms_psrp.PipelineState_Completed || RunSpacePool.PipelineState==ms_psrp.PipelineState_Failed){
                NSLog(@"PipelineState_Completed");
                
                if(RunSpacePool.PipelineState==ms_psrp.PipelineState_Failed){
                    NSLog(@"failure");
                    
                    NSMutableDictionary *outputDict=[ms_psrp parseOutputForObject:decodedXML];
                    [delegate showOutput:outputDict];
                }
                
                //terminate command, let console decide if shell is completed
                [self signal];
                [delegate commandCompleted];
                
                return;
            }
            
            
        }//End of Pipeline State
        
    }//End Of stdout parsing
    
    //receive again until we get a pipeline state
    //[self receive];
    
    NSArray *stateArray=[envelope nodesForXPath:@"//rsp:CommandState" error:nil];
    
    for(int i=0;i<[stateArray count];i++){
        GDataXMLElement *cmdState=(GDataXMLElement*)[stateArray objectAtIndex:i];
        NSLog(@"Command State: %@",[cmdState XMLString]);
        
        GDataXMLNode *state=[cmdState attributeForName:@"State"];
        
        NSLog(@"State: %@",[state stringValue]);
    }
    
    NSLog(@"End of receive response");
    //[delegate commandCompleted];
    [self receive];
}

-(void)commandResponse: (GDataXMLDocument*)envelope{
    
    GDataXMLNode *relatesToXml=[[envelope nodesForXPath:@"//a:RelatesTo" error:nil] lastObject];
    NSString *relatesToID=relatesToXml.stringValue;
    NSLog(@"relates to %@",relatesToID);
    
    NSArray *results=[envelope nodesForXPath:@"//rsp:CommandId" error:nil];
    
    for(int i=0;i<[results count];i++){
        GDataXMLNode *commandXml = [results objectAtIndex:0];
        Shell.CommandId=commandXml.stringValue;
        NSLog(@"CommandId %@",Shell.CommandId);
        
        [self receive];
    }
    
    NSArray *stateArray=[envelope nodesForXPath:@"//rsp:CommandState" error:nil];
    
    for(int i=0;i<[stateArray count];i++){
        NSLog(@"Command State: %@",[(GDataXMLElement*)[stateArray objectAtIndex:i] XMLString]);
    }
}

-(void)sendResponse: (GDataXMLDocument*)envelope{
    
    //Receive Envelope
    //MS-PSRP 3.1.5.3.7 Rules for the wxf:Receive Message
    GDataXMLElement *receiveEnvelope=[ms_wsmv xmlEnvelope];
    NSString *receiveMessageId=[self generateUUID];
    GDataXMLElement *receiveHeader=[ms_wsmv xmlEnvelopeReceiveHeaderTo:To MessageID:receiveMessageId ShellID:Shell.ShellID CommandId:nil];
    [receiveEnvelope addChild:receiveHeader];
    GDataXMLElement *receieveBody=[ms_wsmv xmlEnvelopeReceiveBodyForCommandId:Shell.CommandId];
    [receiveEnvelope addChild:receieveBody];
    
    NSData *receiveData=[receiveEnvelope.XMLString dataUsingEncoding:NSUTF8StringEncoding];
    [self SendRequestWithHTTPBody:receiveData];
}

-(void)faultResponse: (GDataXMLDocument*)envelope{

    GDataXMLNode *relatesToXml=[[envelope nodesForXPath:@"//a:RelatesTo" error:nil] lastObject];
    NSString *relatesToID=relatesToXml.stringValue;
    
    //NSString *fullmessage=[[NSString alloc] initWithData:envelope.XMLData encoding:NSUTF8StringEncoding];
    //NSLog(@"fault: %@",fullmessage);
    
    NSArray *results=[envelope nodesForXPath:@"//s:Text | //*[@provider='microsoft.powershell']" error:nil];
    
    //NSLog(@"results %@",results);
    
    for(int i=0;i<[results count];i++){
        GDataXMLNode *faultXml = [results objectAtIndex:i];
        NSString *fault=faultXml.stringValue;
        NSLog(@"fault: %@",fault);
        if([relatesToID isEqualToString:[NSString stringWithFormat:@"uuid:%@", terminateMessageID]]){
            NSLog(@"Fault is in response to Terminate message, will not show");
        }
        else if([fault isEqualToString:@"The WS-Management service cannot process the request because the request contained invalid selectors for the resource. "]){
            
            NSMutableDictionary *outputDict=[[NSMutableDictionary alloc] init];
            [outputDict setValue:@"Session Broken" forKey:@"Output"];
            
            [delegate showOutput:outputDict];
        }
        else{
            //NSString *fault = [nsstri
            //NSLog(@"fault: %@",[envelope nodesForXPath:@"//body" error:nil]);
            NSMutableDictionary *outputDict=[[NSMutableDictionary alloc] init];
            [outputDict setValue:fault forKey:@"Output"];
            
            [delegate showOutput:outputDict];
        }
    }
    
    [delegate showStatus:@"Disconnected"];
}

#pragma mark - RestKit

-(void)SendRequestWithHTTPBody:(NSData*)httpbody{
    
    [delegate showStatus:@"Sending"];
    
    NSDictionary *Headers;
    RKRequest * request = [[RKClient sharedClient] requestWithResourcePath:ResourcePath];
    [request setDelegate:self];
    [request setMethod:RKRequestMethodPOST];

    if(!authNegotiate){
        Headers=[NSDictionary dictionaryWithObject:@"application/soap+xml;charset=UTF-8"
                                            forKey:@"Content-Type"];}
    else{
        NSString *length=@"0";
        
        //save the data in case we have to re-authenticate later
        pendingData=httpbody;
        
        httpbody=[self encryptMessage:httpbody];
        length=[NSString stringWithFormat:@"%d",[httpbody length]];
        
        Headers=[NSDictionary dictionaryWithObjectsAndKeys:
                 @"multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"",@"Content-Type",
                 @"Keep-Alive",@"Connection",
                 @"Microsoft WinRM Client",@"User-Agent",
                 length,@"Content-Length",
                 nil];
    }
    
    [request setAdditionalHTTPHeaders:Headers];
    [request setHTTPBody:httpbody];

    //send is asynchronous, therefore this message controller must be retained so that it is not deallocated before reskit responds
    
    [request send];
}

-(NSString*)generateUUID{
    CFUUIDRef theUUID = CFUUIDCreate(NULL);
    CFStringRef string = CFUUIDCreateString(NULL, theUUID);
    return [NSString stringWithFormat:@"%@",string];
}



-(void)requestDidTimeout:(RKRequest *)request{
    NSLog(@"requestDidTimeout");
}

-(void)request:(RKRequest *)request didFailLoadWithError:(NSError *)error{
    NSLog(@"request error %d error: %@",[error code],[error localizedDescription]);
    
    if([error code]==-1012){
        NSLog(@"Failed authentication challenge");
        NSMutableDictionary *outputDict=[[NSMutableDictionary alloc] init];
        [outputDict setValue:@"Unauthorized" forKey:@"Output"];
        
        [delegate showOutput:outputDict];
    }
    else if([error code]==-1001){
        NSLog(@"The request timed out");
        NSMutableDictionary *outputDict=[[NSMutableDictionary alloc] init];
        [outputDict setValue:[error localizedDescription] forKey:@"Output"];
        
        [delegate showOutput:outputDict];
        //need to decide when we can show the prompt again
        //[delegate commandCompleted];
    }
    else{
        NSMutableDictionary *outputDict=[[NSMutableDictionary alloc] init];
        [outputDict setValue:[error localizedDescription] forKey:@"Output"];
        
        [delegate showOutput:outputDict];
        [delegate showStatus:@"Disconnected"];
    }
}

-(void)request:(RKRequest*)request didLoadResponse:(RKResponse*)response { 
    NSLog(@"didLoadResponse");
    
    //error code 200 = everything perfect
    //error code 400 = HTTP Body (encrypted message) headers or server could not decrypt message
    //error code 401 = credentials are wrong or you sent unencrypted data
    //error code 405 = Invalid Method (probably GET)
    //error code 415 = Server didn't expect encrypted data
    //error code 500 = Terminate message 
    
    //for testing;
    if([response statusCode]==405){
         [delegate gotAResponse];
    }
    
    if([response isUnauthorized]){
        NSLog(@"headers: %@",[response allHeaderFields]);
        
        if(authNegotiate){
            
            NTLM_CONTEXT *ntlm=sspi_SecureHandleGetLowerPointer(&context);
            if(ntlm->state==NTLM_STATE_CHALLENGE){
                NSLog(@"401 Negotiate");
                [self ntlm_authenticateWithResponseHeaders:[response allHeaderFields]];
                return;
            }
            
            if(ntlm->state==NTLM_STATE_FINAL){
#warning can we predict when a session will be broken?
                if(unAuthCount<1){
                    NSLog(@"\n\nSession Broken. Reconnecting...\n\n");
                    unAuthCount++;
                    
                    //try to get a new session
                    table->FreeContextBuffer(&context);
                    [self initSSPIContext];
                    [self ntlm_negotiate];
                    
                    return;
                }
            }
        }
        
        NSMutableDictionary *outputDict=[[NSMutableDictionary alloc] init];
        [outputDict setValue:@"Write1" forKey:@"Method"];
        [outputDict setValue:@"Unauthorized" forKey:@"Output"];
        
        [delegate showOutput:outputDict];
        [delegate showStatus:@"Disconnected"];
        
        return;
    }
    
    unAuthCount=0;
    NSData *responseData;
    
    if(![[response body] length]){
        NSLog(@"Response is empty, nothing to do");
        return;
    }
    
    if(authNegotiate){
        NSLog(@"Need to Decrypt message");
        responseData=[self decryptMessage:[response body]];
        
        NSString *decryptedMessage=[[NSString alloc] initWithData:responseData encoding:NSUTF8StringEncoding];
        NSLog(@"decryptedMessage: %@",decryptedMessage);
    }
    else{
        responseData=[response body];
    }
    
    //NSLog(@"responseString: %@",response.bodyAsString);
    
    // MS-PSRP 3.1.5 Message Processing Events and Sequencing Rules
    // MS-PSRP 3.1.5.1 General Rules
    
    NSLog(@"responseData: %@",[responseData description]);
    
    NSData *gt=[@">" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *last=[responseData subdataWithRange:NSMakeRange([responseData length]-1, 1)];
    
    NSLog(@"%@ ? %@",[gt description],[last description]);
    
    if(![last isEqualToData:gt]){
        NSLog(@"invalid XML");
        
        NSRange range=[responseData rangeOfData:gt options:NSDataSearchBackwards range:NSMakeRange(0, [responseData length])];
        
        if(range.location==NSNotFound){
            NSLog(@"couldn't fix XML");
        }
        else{
            responseData=[responseData subdataWithRange:NSMakeRange(0,range.location+1)];
            NSLog(@"fixed xml: %@",[responseData description]);
        }
        
    }
    
    
    
    NSString *responseString=[[NSString alloc] initWithData:responseData encoding:NSUTF8StringEncoding];
    NSLog(@"responseString: %@",responseString);
    
    NSError *error;
    GDataXMLDocument *envelope = [[GDataXMLDocument alloc] initWithData:responseData options:0 error:&error];
    
    if(error){
        NSLog(@"error: %@",[error localizedDescription]);
    }
    
    //Every Valid Response should have an action
    NSArray *action=[envelope nodesForXPath:@"//a:Action" error:nil];
    
    NSString *actionString;
    if([action count]>0){
        actionString=[(GDataXMLNode*)[action objectAtIndex:0] stringValue];
        NSLog(@"Action: %@",actionString);
    }
    else{
        NSLog(@"Didn't get a valid response");
        [delegate showOutput:[NSMutableDictionary dictionaryWithObject:@"Unable to parse response" forKey:@"Output"]];
        [delegate showStatus:@"Disconnected"];
        return;
    }
    
    //CreateResponse
    //MS-PSRP 3.1.5.3.2 Rules for the wxf:ResourceCreated Message
    if([actionString isEqualToString:@"http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse"]){
        NSLog(@"CreateResponse");
        [self createResponse:envelope];
    }
    
    //ReceiveResponse
    //MS-PSRP 3.1.5.3.8 Rules for the wxf:ReceiveResponse Message
    if([actionString isEqualToString:@"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse"]){
        NSLog(@"ReceiveResponse");
        [self receiveResponse:envelope];
        
    }// End Of ReceiveResponse
    
    //CommandResponse
    //MS-PSRP 3.1.5.3.4 Rules for the wxf:CommandResponse Message
    if([actionString isEqualToString:@"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse"]){
        NSLog(@"CommandResponse");
        [self commandResponse:envelope];
    }//End of CommandResponse
    
    //SendResponse
    //MS-PSRP 3.1.5.3.6 Rules for the wxf:SendResponse Message
    if([actionString isEqualToString:@"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SendResponse"]){
        NSLog(@"SendResponse");

        //NSLog(@"envelope: %@",response.bodyAsString);
        
        [self sendResponse:envelope];
        
    }
    
    //FaultResponse
    //MS-PSRP 3.1.5.3.13 Rules for the wxf:Fault Message
    if([actionString isEqualToString:@"http://schemas.dmtf.org/wbem/wsman/1/wsman/fault"] || [actionString isEqualToString:@"http://schemas.xmlsoap.org/ws/2004/08/addressing/fault"]){
        NSLog(@"FaultResponse");
        [self faultResponse:envelope];
    }
    
    //DeleteResponse
    //MS-PSRP 3.1.5.3.12 Rules for the wxf:DeleteResponse Message
    if([actionString isEqualToString:@"http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse"]){
        NSLog(@"DeleteResponse");
        [delegate showStatus:@"Disconnected"];
        [delegate deleteCompleted];
    }
    
}

- (void)requestWillPrepareForSend:(RKRequest *)request{
    NSLog(@"requestWillPrepareForSend");
}

-(void)request:(RKRequest *)request didReceiveResponse:(RKResponse *)response{
    NSLog(@"didReceiveResponse");
    //NSURLResponse *urlresponse=[response ]
    
}

-(void)requestDidStartLoad:(RKRequest *)request{
    NSLog(@"requestDidStartLoad");
}

-(void)request:(RKRequest *)request didSendBodyData:(NSInteger)bytesWritten totalBytesWritten:(NSInteger)totalBytesWritten totalBytesExpectedToWrite:(NSInteger)totalBytesExpectedToWrite{
    [delegate showStatus:@"Sending"];
    //NSLog(@"didSendBodyData: %@",[request HTTPBodyString]);
}

-(void)request:(RKRequest *)request didReceiveData:(NSInteger)bytesReceived totalBytesReceived:(NSInteger)totalBytesReceived totalBytesExpectedToReceive:(NSInteger)totalBytesExpectedToReceive{
    [delegate showStatus:@"Receiving"];
    NSLog(@"didReceiveData");
    
}

@end
