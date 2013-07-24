//
//  MS-WSMV.h
//  powershell
//
//  Created by Joshua Langford on 8/17/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//
//  MS-WSMV - http://msdn.microsoft.com/en-us/library/cc251526(v=prot.10).aspx

#import <Foundation/Foundation.h>

@class GDataXMLElement;
@class GDataXMLNode;

@interface MS_WSMV : NSObject

@property (nonatomic,retain) GDataXMLNode *xmlns_xml;
@property (nonatomic,retain) GDataXMLNode *xmlns_s;
@property (nonatomic,retain) GDataXMLNode *xmlns_a;
@property (nonatomic,retain) GDataXMLNode *xmlns_w;
@property (nonatomic,retain) GDataXMLNode *xmlns_p;
@property (nonatomic,retain) GDataXMLNode *xmlns_xsi;
@property (nonatomic,retain) GDataXMLNode *xmlns_rsp;

-(GDataXMLElement*)xmlEnvelope;
-(GDataXMLElement*)xmlEnvelopeCreateHeaderTo: (NSString*)to MessageID:(NSString*)messageid;
-(GDataXMLElement*)xmlEnvelopeCreateBodyWithCreationXML: (NSString*)creationxml;

-(GDataXMLElement*)xmlEnvelopeReceiveHeaderTo: (NSString*)to MessageID:(NSString*)messageid ShellID:(NSString*)shellid CommandId:(NSString*)commandid;
-(GDataXMLElement*)xmlEnvelopeReceiveBodyForCommandId: (NSString*)commandid;

-(GDataXMLElement*)xmlEnvelopeCommandHeaderTo: (NSString*)to MessageID:(NSString*)messageid ShellID:(NSString*)shellid;
-(GDataXMLElement*)xmlEnvelopeCommandBodyWithArgs: (NSString*)arguments;

-(GDataXMLElement*)xmlEnvelopeSendHeaderTo: (NSString*)to MessageID:(NSString*)messageid ShellID:(NSString*)shellid CommandId:(NSString*)commandid;
-(GDataXMLElement*)xmlEnvelopeSendBodyForCommandId: (NSString*)commandid Args:(NSString*)args;

-(GDataXMLElement*)xmlEnvelopeSignalHeaderTo: (NSString*)to MessageID:(NSString*)messageid ShellID:(NSString*)shellid CommandId:(NSString*)commandid;
-(GDataXMLElement*)xmlEnvelopeSignalBodyForCommandId: (NSString*)commandid;

-(GDataXMLElement*)xmlEnvelopeDeleteHeaderTo: (NSString*)to MessageID:(NSString*)messageid ShellID:(NSString*)shellid;
-(GDataXMLElement*)xmlEnvelopeDeleteBody;


@end
