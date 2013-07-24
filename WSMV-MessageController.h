//
//  WSMV-MessageController.h
//  powershell
//
//  Created by Joshua Langford on 8/27/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//
//  Workflow - Used to maintain an orderly collection of messages between client and server
//  Workflow coordinates between NLMP, WSMV, and PSRP to create messages

#import <Foundation/Foundation.h>
#import <RestKit/RestKit.h>

@class MS_WSMV;
@class MS_PSRP;
@class MS_NLMP;
@class WSMV_Shell;
@class PSRP_RunSpacePool;
@class Server;

@protocol wsmv_delegate <NSObject>
-(void)shellCreated;
-(void)commandCompleted;
-(void)deleteCompleted;
-(void)showOutput:(NSMutableDictionary*)outputdict;
-(void)showStatus:(NSString*)status;

@optional

-(void)gotAResponse;

@end


@interface WSMV_MessageController : NSObject <RKRequestDelegate,NSURLConnectionDelegate>

@property (nonatomic,retain) id<wsmv_delegate>delegate;

@property (nonatomic,retain) Server *CurrentServer;
@property (nonatomic,copy) NSString *ResourcePath;
@property (nonatomic,copy) NSString *To;

@property (nonatomic,copy) NSString *Script;
@property (nonatomic,retain) MS_WSMV *ms_wsmv;
@property (nonatomic,retain) MS_PSRP *ms_psrp;
@property (nonatomic,retain) MS_NLMP *ms_nlmp;

@property (nonatomic,retain) WSMV_Shell *Shell;
@property (nonatomic,retain) PSRP_RunSpacePool *RunSpacePool;

@property (nonatomic,retain) NSData *pendingData;
@property (nonatomic,assign) BOOL authNegotiate;
@property (nonatomic,assign) int unAuthCount;

-(void)send:(NSMutableDictionary*)input;
-(void)getWSMAN;
-(void)createShell;
-(void)deleteShell;
-(NSString*)command:(NSString*)script;

-(NSString*)generateUUID;
-(void)SendRequestWithHTTPBody:(NSData*)httpbody;

-(void)setServer: (Server*)server;

@end
