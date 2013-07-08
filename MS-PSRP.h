//
//  MS-PSRP.h
//  powershell
//
//  Created by Joshua Langford on 8/22/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//
//  MS-PSRP - http://msdn.microsoft.com/en-us/library/dd357801.aspx

#import <Foundation/Foundation.h>

@class GDataXMLDocument;
@class GDataXMLElement;

@interface MS_PSRP : NSObject

@property (nonatomic,assign) uint32_t destServer;
@property (nonatomic,assign) uint32_t destClient;
@property (nonatomic,retain) NSData *pid0;
@property (nonatomic,retain) NSData *bom;
@property (nonatomic,assign) uint64_t objectID;
@property (nonatomic,assign) uint64_t fragmentID;
//@property (nonatomic,assign) unsigned char fragmentOrder;

@property (nonatomic,assign) uint8_t fragment_Middle;
@property (nonatomic,assign) uint8_t fragment_End;
@property (nonatomic,assign) uint8_t fragment_Start;
@property (nonatomic,assign) uint8_t fragment_StartAndEnd;

@property (nonatomic,assign) uint32_t msgType_SESSION_CAPABILITY;
@property (nonatomic,assign) uint32_t msgType_INIT_RUNSPACEPOOL;
@property (nonatomic,assign) uint32_t msgType_APPLICATION_PRIVATE_DATA;
@property (nonatomic,assign) uint32_t msgType_RUNSPACEPOOL_STATE;
@property (nonatomic,assign) uint32_t msgType_CREATE_PIPELINE;
@property (nonatomic,assign) uint32_t msgType_PIPELINE_STATE;
@property (nonatomic,assign) uint32_t msgType_PIPELINE_INPUT;
@property (nonatomic,assign) uint32_t msgType_PIPELINE_OUTPUT;
@property (nonatomic,assign) uint32_t msgType_PIPELINE_HOST_CALL;
@property (nonatomic,assign) uint32_t msgType_PIPELINE_HOST_RESPONSE;
@property (nonatomic,assign) uint32_t msgType_ERROR_RECORD;
@property (nonatomic,assign) uint32_t msgType_GET_COMMAND_METADATA;

@property (nonatomic,assign) uint32_t RunspacePoolState_BeforeOpen;
@property (nonatomic,assign) uint32_t RunspacePoolState_Opening;
@property (nonatomic,assign) uint32_t RunspacePoolState_Opened;
@property (nonatomic,assign) uint32_t RunspacePoolState_Closed;
@property (nonatomic,assign) uint32_t RunspacePoolState_Closing;
@property (nonatomic,assign) uint32_t RunspacePoolState_Broken;
@property (nonatomic,assign) uint32_t RunspacePoolState_NegotiationSent;
@property (nonatomic,assign) uint32_t RunspacePoolState_NegotiationSucceeded;
@property (nonatomic,assign) uint32_t RunspacePoolState_Connecting;
@property (nonatomic,assign) uint32_t RunspacePoolState_Disconnected;

@property (nonatomic,assign) uint32_t PipelineState_Notstarted;
@property (nonatomic,assign) uint32_t PipelineState_Running;
@property (nonatomic,assign) uint32_t PipelineState_Stopping;
@property (nonatomic,assign) uint32_t PipelineState_Stopped;
@property (nonatomic,assign) uint32_t PipelineState_Completed;
@property (nonatomic,assign) uint32_t PipelineState_Failed;
@property (nonatomic,assign) uint32_t PipelineState_Disconnected;

-(NSMutableData*)xml_NewShellWithRPID:(NSString*)rpid;
-(NSString*)xml_SESSION_CAPABILITY;
-(NSString*)xml_INIT_RUNSPACEPOOL;
-(NSMutableData*)xml_CREATE_PIPELINEwithRPID:(NSString*)rpid PID:(NSString*)pid UnicodeScript:(NSString*)unicodescript;
-(NSData*)xml_PIPELINE_HOST_RESPONSEwithRPID:(NSString *)rpid PID:(NSString *)pid Key:(NSString *)key Value:(NSString*)value;
-(NSData*)xml_GET_COMMAND_METADATAwithRPID:(NSString *)rpid PID:(NSString *)pid;

-(NSMutableDictionary*)parseOutputForObject:(GDataXMLDocument*)object;
-(NSMutableDictionary*)parseErrorOutput:(GDataXMLElement*)xerror addToDict:(NSMutableDictionary*)outputdict;
-(NSMutableDictionary*)parseGetHelpOutput:(GDataXMLElement*)xgethelp addToDict:(NSMutableDictionary*)outputdict;
-(NSMutableDictionary*)parseExtendedProperties:(GDataXMLElement*)xproperties ofType:(NSString*)type addToDict:(NSMutableDictionary*)outputdict;

@end
