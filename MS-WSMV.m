//
//  MS-WSMV.m
//  powershell
//
//  Created by Joshua Langford on 8/17/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

//Namespaces MS-WSMV 2.2.1
/*
 xmlns_xml
    NSString *lang

 xmlns_s
    NSString *ElementEnvelopeTag;
    NSString *ElementHeaderTag;
    NSString *ElementBodyTag;
    NSString *Attribute_mustUnderstand;
 
 xmlns_a
    NSString *ElementToTag;
    NSString *ElementReplyToTag;
    NSString *ElementAddressTag;
    NSString *ElementActionTag;
    NSString *ElementMessageIDTag;
 
 xmlns_w
    NSString *ElementResourceURITag;
    NSString *ElementMaxEnvelopeSizeTag;
    NSString *ElementLocaleTag;
    NSString *ElementOptionSetTag;
    NSString *ElementOptionTag;
    NSString *ElementOperationTimeoutTag;
    NSString *Attribute_Name;
    NSString *Attribute_MustComply;

 xmlns_p
    NSString *ElementDataLocaleTag;
 
 xmlns_xsi

 xmlns_rsp
    NSString *ElementShellTag;
    NSString *ElementIdleTimeOutTag;
    NSString *ElementInputStreamsTag;
    NSString *ElementOutputStreamsTag;
*/

//Unused Namespaces
/* 
NSString *const WSMV_Namespace_Attribute_xs = @"xmlns:xs";
NSString *const WSMV_Namespace_Attribute_xs_value = @"http://www.w3.org/2001/XMLSchema";
NSString *const WSMV_Namespace_Attribute_wsmid = @"xmlns:wsmid";
NSString *const WSMV_Namespace_Attribute_wsmid_value = @"http://schemas.dmtf.org/wbem/wsman/identify/1/wsmanidentity.xsd";
NSString *const WSMV_Namespace_Attribute_wsmanfault = @"xmlns:wsmanfault";
NSString *const WSMV_Namespace_Attribute_wsmanfault_value = @"http://schemas.microsoft.com/wbem/wsman/1/wsmanfault";
NSString *const WSMV_Namespace_Attribute_cim = @"xmlns:cim";
NSString *const WSMV_Namespace_Attribute_cim_value = @"http://schemas.dmtf.org/wbem/wscim/1/common";
NSString *const WSMV_Namespace_Attribute_wsmv = @"xmlns:p";
NSString *const WSMV_Namespace_Attribute_wsmv_value = @"http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd";
NSString *const WSMV_Namespace_Attribute_cfg = @"xmlns:cfg";
NSString *const WSMV_Namespace_Attribute_cfg_value = @"http://schemas.microsoft.com/wbem/wsman/1/config";
NSString *const WSMV_Namespace_Attribute_sub = @"xmlns:sub";
NSString *const WSMV_Namespace_Attribute_sub_value = @"http://schemas.microsoft.com/wbem/wsman/1/subscription";
NSString *const WSMV_Namespace_Attribute_m = @"xmlns:m";
NSString *const WSMV_Namespace_Attribute_m_value = @"http://schemas.microsoft.com/wbem/wsman/1/machineid";
NSString *const WSMV_Namespace_Attribute_cert = @"xmlns:cert";
NSString *const WSMV_Namespace_Attribute_cert_value = @"http://schemas.microsoft.com/wbem/wsman/1/config/service/certmapping";
NSString *const WSMV_Namespace_Attribute_plugin = @"xmlns:plugin";
NSString *const WSMV_Namespace_Attribute_plugin_value = @"http://schemas.microsoft.com/wbem/wsman/1/config/PluginConfiguration";
NSString *const WSMV_Namespace_Attribute_wsen = @"xmlns:wsen";
NSString *const WSMV_Namespace_Attribute_wsen_value = @"http://schemas.xmlsoap.org/ws/2004/09/enumeration";
NSString *const WSMV_Namespace_Attribute_wsdln = @"xmlns:wsdl";
NSString *const WSMV_Namespace_Attribute_wsdl_value = @"http://schemas.xmlsoap.org/wsdl";
NSString *const WSMV_Namespace_Attribute_wst = @"xmlns:wst";
NSString *const WSMV_Namespace_Attribute_wst_value = @"http://schemas.xmlsoap.org/ws/2004/09/transfer";
NSString *const WSMV_Namespace_Attribute_wsp = @"xmlns:wsp";
NSString *const WSMV_Namespace_Attribute_wsp_value = @"http://schemas.xmlsoap.org/ws/2004/09/policy";
NSString *const WSMV_Namespace_Attribute_wse = @"xmlns:wse";
NSString *const WSMV_Namespace_Attribute_wse_value = @"http://schemas.xmlsoap.org/ws/2004/08/eventing";
NSString *const WSMV_Namespace_Attribute_i = @"xmlns:i";
NSString *const WSMV_Namespace_Attribute_i_value = @"http://schemas.microsoft.com/wbem/wsman/1/cim/interactive.xsd";
*/

#import "MS-WSMV.h"

#import "GDataXMLNode.h"

@interface MS_WSMV (){
    int SequenceID;
}

@end

#pragma mark code

@implementation MS_WSMV

@synthesize xmlns_xml;
@synthesize xmlns_s;
@synthesize xmlns_a;
@synthesize xmlns_w;
@synthesize xmlns_p;
@synthesize xmlns_xsi;
@synthesize xmlns_rsp;

-(id)init{
    
    if(self==[super init]){
        xmlns_xml = [GDataXMLNode namespaceWithName:@"xml" stringValue:@"http://www.w3.org/2001/XMLSchema.dtd"];
        xmlns_s   = [GDataXMLNode namespaceWithName:@"s" stringValue:@"http://www.w3.org/2003/05/soap-envelope"];
        xmlns_a   = [GDataXMLNode namespaceWithName:@"a" stringValue:@"http://schemas.xmlsoap.org/ws/2004/08/addressing"];
        xmlns_w   = [GDataXMLNode namespaceWithName:@"w" stringValue:@"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"];
        xmlns_p   = [GDataXMLNode namespaceWithName:@"p" stringValue:@"http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"];
        xmlns_xsi = [GDataXMLNode namespaceWithName:@"xsi" stringValue:@"http://www.w3.org/2001/XMLSchema-instance"];
        xmlns_rsp = [GDataXMLNode namespaceWithName:@"rsp" stringValue:@"http://schemas.microsoft.com/wbem/wsman/1/windows/shell"];
        
        SequenceID=0;
    }
    
    return self;
}

//Set up bare envelope with namespaces that will be common to all messages
-(GDataXMLElement*)xmlEnvelope{
    
    GDataXMLElement *envelope=[GDataXMLElement elementWithName:@"Envelope" URI:xmlns_s.stringValue];
    [envelope addNamespace:xmlns_s];
    [envelope addNamespace:xmlns_a];
    [envelope addNamespace:xmlns_w];
    [envelope addNamespace:xmlns_p];
    [envelope addNamespace:xmlns_xml];
    
    return envelope;
}

#pragma mark Create
-(GDataXMLElement*)xmlEnvelopeCreateHeaderTo: (NSString*)to MessageID:(NSString*)messageid{
    
    GDataXMLElement *header=[GDataXMLElement elementWithName:@"Header" URI:xmlns_s.stringValue];
    
    GDataXMLElement *To=[GDataXMLElement elementWithName:@"To" URI:xmlns_a.stringValue];
    [To setStringValue:to];
    [header addChild:To];
    
    //resourceuri
    GDataXMLElement *ResourceURI=[GDataXMLElement elementWithName:@"ResourceURI" URI:xmlns_w.stringValue];
    [ResourceURI setStringValue:@"http://schemas.microsoft.com/powershell/Microsoft.PowerShell"];
    GDataXMLNode *mustUnderstand=[GDataXMLNode attributeWithName:@"mustUnderstand" URI:xmlns_s.stringValue stringValue:@"true"];
    [ResourceURI addAttribute:mustUnderstand];
    [header addChild:ResourceURI];
    
    //replyto
    GDataXMLElement *ReplyTo=[GDataXMLElement elementWithName:@"ReplyTo" URI:xmlns_a.stringValue];
    GDataXMLElement *Address=[GDataXMLElement elementWithName:@"Address" URI:xmlns_a.stringValue];
    //mustunderstand
    [Address addAttribute:mustUnderstand];
    [Address setStringValue:@"http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"];
    [ReplyTo addChild:Address];
    [header addChild:ReplyTo];
    
    //action
    GDataXMLElement *Action=[GDataXMLElement elementWithName:@"Action" URI:xmlns_a.stringValue];
    //mustunderstand
    [Action addAttribute:mustUnderstand];
    [Action setStringValue:@"http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"];
    [header addChild:Action];
    
    
    GDataXMLElement *MaxEnvelopeSize=[GDataXMLElement elementWithName:@"MaxEnvelopeSize" URI:xmlns_w.stringValue];
    //mustunderstand
    [MaxEnvelopeSize addAttribute:mustUnderstand];
    [MaxEnvelopeSize setStringValue:@"153600"];
    [header addChild:MaxEnvelopeSize];
    
    GDataXMLElement *MessageID=[GDataXMLElement elementWithName:@"MessageID" URI:xmlns_a.stringValue];
    [MessageID setStringValue:[NSString stringWithFormat:@"uuid:%@",messageid]];
    [header addChild:MessageID];
    
    //Locale
    GDataXMLElement *Locale=[GDataXMLElement elementWithName:@"Locale" URI:xmlns_w.stringValue];
    GDataXMLNode *lang=[GDataXMLNode attributeWithName:@"xml:lang" stringValue:@"en-US"];
    [Locale addAttribute:lang];
    GDataXMLNode *mustUnderstandFalse=[GDataXMLNode attributeWithName:@"mustUnderstand" URI:xmlns_s.stringValue stringValue:@"false"];
    [Locale addAttribute:mustUnderstandFalse];
    [header addChild:Locale];
    
    GDataXMLElement *DataLocale=[GDataXMLElement elementWithName:@"DataLocale" URI:xmlns_p.stringValue];
    //lang
    [DataLocale addAttribute:lang];
    //mustunderstand
    [DataLocale addAttribute:mustUnderstandFalse];
    [header addChild:DataLocale];
    
    //Options
    GDataXMLElement *OptionSet=[GDataXMLElement elementWithName:@"OptionSet" URI:xmlns_w.stringValue];
    [OptionSet addNamespace:xmlns_xsi];
    [OptionSet addAttribute:mustUnderstand];
    
    GDataXMLElement *Option=[GDataXMLElement elementWithName:@"Option" URI:xmlns_w.stringValue];
    GDataXMLNode *Name=[GDataXMLNode attributeWithName:@"Name" stringValue:@"protocolversion"];
    [Option addAttribute:Name];
    GDataXMLNode *MustComply=[GDataXMLNode attributeWithName:@"MustComply" stringValue:@"true"];
    [Option addAttribute:MustComply];
    [Option setStringValue:@"2.1"];
    [OptionSet addChild:Option];
    [header addChild:OptionSet];
    
    //OperationTimeout
    GDataXMLElement *OperationTimeout=[GDataXMLElement elementWithName:@"OperationTimeout" URI:xmlns_w.stringValue];
    [OperationTimeout setStringValue:@"PT60.000S"];
    [header addChild:OperationTimeout];
    
    //NSLog(@"%@",header);
    
    return header;
}

-(GDataXMLElement*)xmlEnvelopeCreateBodyWithCreationXML: (NSString*)creationxml{
    
    GDataXMLElement *body=[GDataXMLElement elementWithName:@"Body" URI:xmlns_s.stringValue];
    
    //rspshell
    GDataXMLElement *Shell=[GDataXMLElement elementWithName:@"Shell" URI:xmlns_rsp.stringValue];
    [Shell addNamespace:xmlns_rsp];
    
    //rspidletimeout
    GDataXMLNode *IdleTimeOut=[GDataXMLElement elementWithName:@"IdleTimeOut" URI:xmlns_rsp.stringValue];
    [IdleTimeOut setStringValue:@"PT240.000S"];
    [Shell addChild:IdleTimeOut];
    
    //rspinputstreams
    GDataXMLElement *InputStreams=[GDataXMLElement elementWithName:@"InputStreams" URI:xmlns_rsp.stringValue];
    [InputStreams setStringValue:@"stdin pr"];
    [Shell addChild:InputStreams];
    
    //rspoutputstreams
    GDataXMLElement *OutputStreams=[GDataXMLElement elementWithName:@"OutputStreams" URI:xmlns_rsp.stringValue];
    [OutputStreams setStringValue:@"stdout"];
    [Shell addChild:OutputStreams];
    
    //creationxml
    //NSLog(@"creationxml: %@",paramCreationXMLString);
    GDataXMLElement *creationXml=[GDataXMLElement elementWithName:@"creationXml" stringValue:creationxml];
    [creationXml addAttribute:[GDataXMLNode attributeWithName:@"xmlns" stringValue:@"http://schemas.microsoft.com/powershell"]];
    [Shell addChild:creationXml];
    
    [body addChild:Shell];
    
    return body;
}

#pragma mark Receive
-(GDataXMLElement*)xmlEnvelopeReceiveHeaderTo: (NSString*)to MessageID:(NSString*)messageid ShellID:(NSString*)shellid CommandId:(NSString*)commandid{
    
    GDataXMLElement *header=[GDataXMLElement elementWithName:@"Header" URI:xmlns_s.stringValue];
    
    GDataXMLElement *To=[GDataXMLElement elementWithName:@"To" URI:xmlns_a.stringValue];
    [To setStringValue:to];
    [header addChild:To];
    
    //resourceuri
    GDataXMLElement *ResourceURI=[GDataXMLElement elementWithName:@"ResourceURI" URI:xmlns_w.stringValue];
    [ResourceURI setStringValue:@"http://schemas.microsoft.com/powershell/Microsoft.PowerShell"];
    GDataXMLNode *mustUnderstand=[GDataXMLNode attributeWithName:@"mustUnderstand" URI:xmlns_s.stringValue stringValue:@"true"];
    [ResourceURI addAttribute:mustUnderstand];
    [header addChild:ResourceURI];
    
    //replyto
    GDataXMLElement *ReplyTo=[GDataXMLElement elementWithName:@"ReplyTo" URI:xmlns_a.stringValue];
    GDataXMLElement *Address=[GDataXMLElement elementWithName:@"Address" URI:xmlns_a.stringValue];
    //mustunderstand
    [Address addAttribute:mustUnderstand];
    [Address setStringValue:@"http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"];
    [ReplyTo addChild:Address];
    [header addChild:ReplyTo];
    
    //action
    GDataXMLElement *Action=[GDataXMLElement elementWithName:@"Action" URI:xmlns_a.stringValue];
    //mustunderstand
    [Action addAttribute:mustUnderstand];
    [Action setStringValue:@"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"];
    [header addChild:Action];
    
    GDataXMLElement *MaxEnvelopeSize=[GDataXMLElement elementWithName:@"MaxEnvelopeSize" URI:xmlns_w.stringValue];
    //mustunderstand
    [MaxEnvelopeSize addAttribute:mustUnderstand];
    [MaxEnvelopeSize setStringValue:@"153600"];
    [header addChild:MaxEnvelopeSize];
    
    GDataXMLElement *MessageID=[GDataXMLElement elementWithName:@"MessageID" URI:xmlns_a.stringValue];
    [MessageID setStringValue:[NSString stringWithFormat:@"uuid:%@",messageid]];
    [header addChild:MessageID];
    
    //Locale
    GDataXMLElement *Locale=[GDataXMLElement elementWithName:@"Locale" URI:xmlns_w.stringValue];
    GDataXMLNode *lang=[GDataXMLNode attributeWithName:@"xml:lang" stringValue:@"en-US"];
    [Locale addAttribute:lang];
    GDataXMLNode *mustUnderstandFalse=[GDataXMLNode attributeWithName:@"mustUnderstand" URI:xmlns_s.stringValue stringValue:@"false"];
    [Locale addAttribute:mustUnderstandFalse];
    [header addChild:Locale];
    
    GDataXMLElement *DataLocale=[GDataXMLElement elementWithName:@"DataLocale" URI:xmlns_p.stringValue];
    //lang
    [DataLocale addAttribute:lang];
    //mustunderstand
    [DataLocale addAttribute:mustUnderstandFalse];
    [header addChild:DataLocale];
    
    //SelectorSet
    GDataXMLElement *SelectorSet=[GDataXMLElement elementWithName:@"SelectorSet" URI:xmlns_w.stringValue];
    
    if(commandid!=nil){
        [SelectorSet addNamespace:xmlns_w];
        GDataXMLNode *wsman=[GDataXMLNode attributeWithName:@"xmlns" stringValue:xmlns_w.stringValue];
        [SelectorSet addAttribute:wsman];
    }
    
    GDataXMLElement *Selector=[GDataXMLElement elementWithName:@"Selector" URI:xmlns_w.stringValue];
    GDataXMLNode *ShellIdAttr=[GDataXMLNode attributeWithName:@"Name" stringValue:@"ShellId"];
    [Selector addAttribute:ShellIdAttr];
    [Selector setStringValue:shellid];
    [SelectorSet addChild:Selector];
    [header addChild:SelectorSet];
    
    if(commandid==nil){
        //Options
        GDataXMLElement *OptionSet=[GDataXMLElement elementWithName:@"OptionSet" URI:xmlns_w.stringValue];
        [OptionSet addNamespace:xmlns_xsi];
        //[OptionSet addAttribute:mustUnderstand];

        GDataXMLElement *Option=[GDataXMLElement elementWithName:@"Option" URI:xmlns_w.stringValue];
        GDataXMLNode *Name=[GDataXMLNode attributeWithName:@"Name" stringValue:@"WSMAN_CMDSHELL_OPTION_KEEPALIVE"];
        [Option addAttribute:Name];
        [Option setStringValue:@"TRUE"];
        [OptionSet addChild:Option];
        [header addChild:OptionSet];
    }
    
    //OperationTimeout
    GDataXMLElement *OperationTimeout=[GDataXMLElement elementWithName:@"OperationTimeout" URI:xmlns_w.stringValue];
    [OperationTimeout setStringValue:@"PT180.000S"];
    [header addChild:OperationTimeout];
    
    //NSLog(@"%@",header);
    
    return header;
    
}

-(GDataXMLElement*)xmlEnvelopeReceiveBodyForCommandId: (NSString*)commandid{
    
    GDataXMLElement *body=[GDataXMLElement elementWithName:@"Body" URI:xmlns_s.stringValue];
    
    //rspshell
    GDataXMLElement *Receive=[GDataXMLElement elementWithName:@"Receive" URI:xmlns_rsp.stringValue];
    [Receive addNamespace:xmlns_rsp];
    GDataXMLNode *SequenceId=[GDataXMLNode attributeWithName:@"SequenceId" stringValue:[NSString stringWithFormat:@"%d",SequenceID]];
    SequenceID++;
    [Receive addAttribute:SequenceId];
    

    //desiredstream
    GDataXMLElement *DesiredStream=[GDataXMLElement elementWithName:@"rsp:DesiredStream" URI:xmlns_rsp.stringValue];
    [DesiredStream setStringValue:@"stdout"];
    
    if(commandid!=nil){
        GDataXMLNode *CommandIdAttr=[GDataXMLNode attributeWithName:@"CommandId" stringValue:commandid];
        [DesiredStream addAttribute:CommandIdAttr];
    }
    
    [Receive addChild:DesiredStream];
    
    [body addChild:Receive];
    
    return body;
}

#pragma mark Command

-(GDataXMLElement*)xmlEnvelopeCommandHeaderTo: (NSString*)to MessageID:(NSString*)messageid ShellID:(NSString*)shellid{
    
    GDataXMLElement *header=[GDataXMLElement elementWithName:@"Header" URI:xmlns_s.stringValue];
    
    GDataXMLElement *To=[GDataXMLElement elementWithName:@"To" URI:xmlns_a.stringValue];
    [To setStringValue:to];
    [header addChild:To];
    
    //replyto
    GDataXMLElement *ReplyTo=[GDataXMLElement elementWithName:@"ReplyTo" URI:xmlns_a.stringValue];
    GDataXMLElement *Address=[GDataXMLElement elementWithName:@"Address" URI:xmlns_a.stringValue];
    GDataXMLNode *mustUnderstand=[GDataXMLNode attributeWithName:@"mustUnderstand" URI:xmlns_s.stringValue stringValue:@"true"];
    [Address addAttribute:mustUnderstand];
    [Address setStringValue:@"http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"];
    [ReplyTo addChild:Address];
    [header addChild:ReplyTo];
    
    //action
    GDataXMLElement *Action=[GDataXMLElement elementWithName:@"Action" URI:xmlns_a.stringValue];
    //mustunderstand
    [Action addAttribute:mustUnderstand];
    [Action setStringValue:@"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"];
    [header addChild:Action];
    
    GDataXMLElement *MaxEnvelopeSize=[GDataXMLElement elementWithName:@"MaxEnvelopeSize" URI:xmlns_w.stringValue];
    //mustunderstand
    [MaxEnvelopeSize addAttribute:mustUnderstand];
    [MaxEnvelopeSize setStringValue:@"153600"];
    [header addChild:MaxEnvelopeSize];
    
    GDataXMLElement *MessageID=[GDataXMLElement elementWithName:@"MessageID" URI:xmlns_a.stringValue];
    [MessageID setStringValue:[NSString stringWithFormat:@"uuid:%@",messageid]];
    [header addChild:MessageID];
    
    //Locale
    GDataXMLElement *Locale=[GDataXMLElement elementWithName:@"Locale" URI:xmlns_w.stringValue];
    GDataXMLNode *lang=[GDataXMLNode attributeWithName:@"xml:lang" stringValue:@"en-US"];
    [Locale addAttribute:lang];
    GDataXMLNode *mustUnderstandFalse=[GDataXMLNode attributeWithName:@"mustUnderstand" URI:xmlns_s.stringValue stringValue:@"false"];
    [Locale addAttribute:mustUnderstandFalse];
    [header addChild:Locale];
    
    GDataXMLElement *DataLocale=[GDataXMLElement elementWithName:@"DataLocale" URI:xmlns_p.stringValue];
    //lang
    [DataLocale addAttribute:lang];
    //mustunderstand
    [DataLocale addAttribute:mustUnderstandFalse];
    [header addChild:DataLocale];
    
    //resourceuri
    GDataXMLElement *ResourceURI=[GDataXMLElement elementWithName:@"ResourceURI" URI:xmlns_w.stringValue];
    //[ResourceURI addNamespace:xmlns_w];
    GDataXMLNode *xmlns_w2=[GDataXMLNode attributeWithName:@"xmlns:w" stringValue:xmlns_w.stringValue];
    [ResourceURI addAttribute:xmlns_w2];
    [ResourceURI setStringValue:@"http://schemas.microsoft.com/powershell/Microsoft.PowerShell"];
    [header addChild:ResourceURI];
    
    //SelectorSet
    GDataXMLElement *SelectorSet=[GDataXMLElement elementWithName:@"SelectorSet" URI:xmlns_w.stringValue];
    [SelectorSet addAttribute:xmlns_w2];
    GDataXMLNode *wsman=[GDataXMLNode attributeWithName:@"xmlns" stringValue:xmlns_w.stringValue];
    [SelectorSet addAttribute:wsman];
    GDataXMLElement *Selector=[GDataXMLElement elementWithName:@"Selector" URI:xmlns_w.stringValue];
    GDataXMLNode *ShellIdAttr=[GDataXMLNode attributeWithName:@"Name" stringValue:@"ShellId"];
    [Selector addAttribute:ShellIdAttr];
    [Selector setStringValue:shellid];
    [SelectorSet addChild:Selector];
    [header addChild:SelectorSet];
    
    //OperationTimeout
    GDataXMLElement *OperationTimeout=[GDataXMLElement elementWithName:@"OperationTimeout" URI:xmlns_w.stringValue];
    [OperationTimeout setStringValue:@"PT180.000S"];
    [header addChild:OperationTimeout];
    
    //NSLog(@"%@",header);
    
    return header;
    
}

-(GDataXMLElement*)xmlEnvelopeCommandBodyWithArgs: (NSString*)arguments{
    
    GDataXMLElement *body=[GDataXMLElement elementWithName:@"Body" URI:xmlns_s.stringValue];
    
    //CommandLine
    GDataXMLElement *CommandLine=[GDataXMLElement elementWithName:@"CommandLine" URI:xmlns_rsp.stringValue];
    [CommandLine addNamespace:xmlns_rsp];
    [CommandLine setStringValue:@""];
    
    GDataXMLElement *Command=[GDataXMLElement elementWithName:@"Command" URI:xmlns_rsp.stringValue];
    [Command setStringValue:@""];
    [CommandLine addChild:Command];  
    
    GDataXMLElement *Arguments=[GDataXMLElement elementWithName:@"Arguments" URI:xmlns_rsp.stringValue];
    [Arguments setStringValue:arguments];
    [CommandLine addChild:Arguments];    
    
    [body addChild:CommandLine];
    
    return body;
}

#pragma mark Send
-(GDataXMLElement*)xmlEnvelopeSendHeaderTo: (NSString*)to MessageID:(NSString*)messageid ShellID:(NSString*)shellid CommandId:(NSString*)commandid{
    
    GDataXMLElement *header=[GDataXMLElement elementWithName:@"Header" URI:xmlns_s.stringValue];
    
    //to
    GDataXMLElement *To=[GDataXMLElement elementWithName:@"To" URI:xmlns_a.stringValue];
    [To setStringValue:to];
    [header addChild:To];
    
    //replyto
    GDataXMLElement *ReplyTo=[GDataXMLElement elementWithName:@"ReplyTo" URI:xmlns_a.stringValue];
    GDataXMLElement *Address=[GDataXMLElement elementWithName:@"Address" URI:xmlns_a.stringValue];
    //mustunderstand
    GDataXMLNode *mustUnderstand=[GDataXMLNode attributeWithName:@"mustUnderstand" URI:xmlns_s.stringValue stringValue:@"true"];
    [Address addAttribute:mustUnderstand];
    [Address setStringValue:@"http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"];
    [ReplyTo addChild:Address];
    [header addChild:ReplyTo];
    
    
    //action
    GDataXMLElement *Action=[GDataXMLElement elementWithName:@"Action" URI:xmlns_a.stringValue];
    //mustunderstand
    [Action addAttribute:mustUnderstand];
    [Action setStringValue:@"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send"];
    [header addChild:Action];
    
    //envelope size
    GDataXMLElement *MaxEnvelopeSize=[GDataXMLElement elementWithName:@"MaxEnvelopeSize" URI:xmlns_w.stringValue];
    //mustunderstand
    [MaxEnvelopeSize addAttribute:mustUnderstand];
    [MaxEnvelopeSize setStringValue:@"153600"];
    [header addChild:MaxEnvelopeSize];
    
    //messageid
    GDataXMLElement *MessageID=[GDataXMLElement elementWithName:@"MessageID" URI:xmlns_a.stringValue];
    [MessageID setStringValue:[NSString stringWithFormat:@"uuid:%@",messageid]];
    [header addChild:MessageID];
    
    //Locale
    GDataXMLElement *Locale=[GDataXMLElement elementWithName:@"Locale" URI:xmlns_w.stringValue];
    GDataXMLNode *lang=[GDataXMLNode attributeWithName:@"xml:lang" stringValue:@"en-US"];
    [Locale addAttribute:lang];
    GDataXMLNode *mustUnderstandFalse=[GDataXMLNode attributeWithName:@"mustUnderstand" URI:xmlns_s.stringValue stringValue:@"false"];
    [Locale addAttribute:mustUnderstandFalse];
    [header addChild:Locale];
    
    GDataXMLElement *DataLocale=[GDataXMLElement elementWithName:@"DataLocale" URI:xmlns_p.stringValue];
    //lang
    [DataLocale addAttribute:lang];
    //mustunderstand
    [DataLocale addAttribute:mustUnderstandFalse];
    [header addChild:DataLocale];
    
    //resourceuri
    GDataXMLElement *ResourceURI=[GDataXMLElement elementWithName:@"ResourceURI" URI:xmlns_w.stringValue];
    //[ResourceURI addNamespace:xmlns_w];
    GDataXMLNode *xmlns_w2=[GDataXMLNode attributeWithName:@"xmlns:w" stringValue:xmlns_w.stringValue];
    [ResourceURI addAttribute:xmlns_w2];
    [ResourceURI setStringValue:@"http://schemas.microsoft.com/powershell/Microsoft.PowerShell"];
    [header addChild:ResourceURI];
    
    //SelectorSet
    GDataXMLElement *SelectorSet=[GDataXMLElement elementWithName:@"SelectorSet" URI:xmlns_w.stringValue];
    [SelectorSet addAttribute:xmlns_w2];
    GDataXMLNode *wsman=[GDataXMLNode attributeWithName:@"xmlns" stringValue:xmlns_w.stringValue];
    [SelectorSet addAttribute:wsman];
    GDataXMLElement *Selector=[GDataXMLElement elementWithName:@"Selector" URI:xmlns_w.stringValue];
    GDataXMLNode *ShellIdAttr=[GDataXMLNode attributeWithName:@"Name" stringValue:@"ShellId"];
    [Selector addAttribute:ShellIdAttr];
    [Selector setStringValue:shellid];
    [SelectorSet addChild:Selector];
    [header addChild:SelectorSet];
    
    //OperationTimeout
    GDataXMLElement *OperationTimeout=[GDataXMLElement elementWithName:@"OperationTimeout" URI:xmlns_w.stringValue];
    [OperationTimeout setStringValue:@"PT60.000S"];
    [header addChild:OperationTimeout];
    
    
    return header;
}

-(GDataXMLElement*)xmlEnvelopeSendBodyForCommandId: (NSString*)commandid Args:(NSString*)args{
    
    GDataXMLElement *body=[GDataXMLElement elementWithName:@"Body" URI:xmlns_s.stringValue];
    
    //Send
    GDataXMLElement *Send=[GDataXMLElement elementWithName:@"Send" URI:xmlns_rsp.stringValue];
    [Send addNamespace:xmlns_rsp];
    
    //Stream
    GDataXMLElement *Stream=[GDataXMLElement elementWithName:@"Stream" URI:xmlns_rsp.stringValue];
    GDataXMLNode *CommandId=[GDataXMLNode attributeWithName:@"CommandId" stringValue:commandid];
    [Stream addAttribute:CommandId];
    GDataXMLNode *Name=[GDataXMLNode attributeWithName:@"Name" stringValue:@"pr"];
    [Stream addAttribute:Name];
    [Stream setStringValue:args];
    
    [Send addChild:Stream];
    [body addChild:Send];
    
    return body;
}

#pragma mark Signal

-(GDataXMLElement*)xmlEnvelopeSignalHeaderTo: (NSString*)to MessageID:(NSString*)messageid ShellID:(NSString*)shellid CommandId:(NSString*)commandid{
    
    GDataXMLElement *header=[GDataXMLElement elementWithName:@"Header" URI:xmlns_s.stringValue];
    
    GDataXMLElement *To=[GDataXMLElement elementWithName:@"To" URI:xmlns_a.stringValue];
    [To setStringValue:to];
    [header addChild:To];
    
    //resourceuri
    GDataXMLElement *ResourceURI=[GDataXMLElement elementWithName:@"ResourceURI" URI:xmlns_w.stringValue];
    [ResourceURI setStringValue:@"http://schemas.microsoft.com/powershell/Microsoft.PowerShell"];
    GDataXMLNode *mustUnderstand=[GDataXMLNode attributeWithName:@"mustUnderstand" URI:xmlns_s.stringValue stringValue:@"true"];
    [ResourceURI addAttribute:mustUnderstand];
    [header addChild:ResourceURI];
    
    //replyto
    GDataXMLElement *ReplyTo=[GDataXMLElement elementWithName:@"ReplyTo" URI:xmlns_a.stringValue];
    GDataXMLElement *Address=[GDataXMLElement elementWithName:@"Address" URI:xmlns_a.stringValue];
    //mustunderstand
    [Address addAttribute:mustUnderstand];
    [Address setStringValue:@"http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"];
    [ReplyTo addChild:Address];
    [header addChild:ReplyTo];
    
    //action
    GDataXMLElement *Action=[GDataXMLElement elementWithName:@"Action" URI:xmlns_a.stringValue];
    //mustunderstand
    [Action addAttribute:mustUnderstand];
    [Action setStringValue:@"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"];
    [header addChild:Action];
    
    GDataXMLElement *MaxEnvelopeSize=[GDataXMLElement elementWithName:@"MaxEnvelopeSize" URI:xmlns_w.stringValue];
    //mustunderstand
    [MaxEnvelopeSize addAttribute:mustUnderstand];
    [MaxEnvelopeSize setStringValue:@"153600"];
    [header addChild:MaxEnvelopeSize];
    
    GDataXMLElement *MessageID=[GDataXMLElement elementWithName:@"MessageID" URI:xmlns_a.stringValue];
    [MessageID setStringValue:[NSString stringWithFormat:@"uuid:%@",messageid]];
    [header addChild:MessageID];
    
    //Locale
    GDataXMLElement *Locale=[GDataXMLElement elementWithName:@"Locale" URI:xmlns_w.stringValue];
    GDataXMLNode *lang=[GDataXMLNode attributeWithName:@"xml:lang" stringValue:@"en-US"];
    [Locale addAttribute:lang];
    GDataXMLNode *mustUnderstandFalse=[GDataXMLNode attributeWithName:@"mustUnderstand" URI:xmlns_s.stringValue stringValue:@"false"];
    [Locale addAttribute:mustUnderstandFalse];
    [header addChild:Locale];
    
    GDataXMLElement *DataLocale=[GDataXMLElement elementWithName:@"DataLocale" URI:xmlns_p.stringValue];
    //lang
    [DataLocale addAttribute:lang];
    //mustunderstand
    [DataLocale addAttribute:mustUnderstandFalse];
    [header addChild:DataLocale];
    
    
    //SelectorSet
    GDataXMLElement *SelectorSet=[GDataXMLElement elementWithName:@"SelectorSet" URI:xmlns_w.stringValue];
    
    [SelectorSet addNamespace:xmlns_w];
    GDataXMLNode *wsman=[GDataXMLNode attributeWithName:@"xmlns" stringValue:xmlns_w.stringValue];
    [SelectorSet addAttribute:wsman];
    
    GDataXMLElement *Selector=[GDataXMLElement elementWithName:@"Selector" URI:xmlns_w.stringValue];
    GDataXMLNode *ShellIdAttr=[GDataXMLNode attributeWithName:@"Name" stringValue:@"ShellId"];
    [Selector addAttribute:ShellIdAttr];
    [Selector setStringValue:shellid];
    [SelectorSet addChild:Selector];
    [header addChild:SelectorSet];
    
    //OperationTimeout
    GDataXMLElement *OperationTimeout=[GDataXMLElement elementWithName:@"OperationTimeout" URI:xmlns_w.stringValue];
    [OperationTimeout setStringValue:@"PT60.000S"];
    [header addChild:OperationTimeout];
    
    //NSLog(@"%@",header);
    
    return header;
    
}

-(GDataXMLElement*)xmlEnvelopeSignalBodyForCommandId: (NSString*)commandid{
    
    GDataXMLElement *body=[GDataXMLElement elementWithName:@"Body" URI:xmlns_s.stringValue];
    
    //Signal
    GDataXMLElement *Signal=[GDataXMLElement elementWithName:@"Signal" URI:xmlns_rsp.stringValue];
    [Signal addNamespace:xmlns_rsp];
    GDataXMLNode *CommandId=[GDataXMLNode attributeWithName:@"CommandId" stringValue:commandid];
    [Signal addAttribute:CommandId];
    
    
    GDataXMLElement *Code=[GDataXMLElement elementWithName:@"Code" URI:xmlns_rsp.stringValue];
    [Code setStringValue:@"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate"];
    [Signal addChild:Code];
    
    [body addChild:Signal];
    
    return body;
}

#pragma mark Delete
-(GDataXMLElement*)xmlEnvelopeDeleteHeaderTo: (NSString*)to MessageID:(NSString*)messageid ShellID:(NSString*)shellid{
    
    GDataXMLElement *header=[GDataXMLElement elementWithName:@"Header" URI:xmlns_s.stringValue];
    
    GDataXMLElement *To=[GDataXMLElement elementWithName:@"To" URI:xmlns_a.stringValue];
    [To setStringValue:to];
    [header addChild:To];
    
    //resourceuri
    GDataXMLElement *ResourceURI=[GDataXMLElement elementWithName:@"ResourceURI" URI:xmlns_w.stringValue];
    [ResourceURI setStringValue:@"http://schemas.microsoft.com/powershell/Microsoft.PowerShell"];
    GDataXMLNode *mustUnderstand=[GDataXMLNode attributeWithName:@"mustUnderstand" URI:xmlns_s.stringValue stringValue:@"true"];
    [ResourceURI addAttribute:mustUnderstand];
    [header addChild:ResourceURI];
    
    //replyto
    GDataXMLElement *ReplyTo=[GDataXMLElement elementWithName:@"ReplyTo" URI:xmlns_a.stringValue];
    GDataXMLElement *Address=[GDataXMLElement elementWithName:@"Address" URI:xmlns_a.stringValue];
    //mustunderstand
    [Address addAttribute:mustUnderstand];
    [Address setStringValue:@"http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"];
    [ReplyTo addChild:Address];
    [header addChild:ReplyTo];
    
    //action
    GDataXMLElement *Action=[GDataXMLElement elementWithName:@"Action" URI:xmlns_a.stringValue];
    //mustunderstand
    [Action addAttribute:mustUnderstand];
    [Action setStringValue:@"http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"];
    [header addChild:Action];
    
    GDataXMLElement *MaxEnvelopeSize=[GDataXMLElement elementWithName:@"MaxEnvelopeSize" URI:xmlns_w.stringValue];
    //mustunderstand
    [MaxEnvelopeSize addAttribute:mustUnderstand];
    [MaxEnvelopeSize setStringValue:@"153600"];
    [header addChild:MaxEnvelopeSize];
    
    GDataXMLElement *MessageID=[GDataXMLElement elementWithName:@"MessageID" URI:xmlns_a.stringValue];
    [MessageID setStringValue:[NSString stringWithFormat:@"uuid:%@",messageid]];
    [header addChild:MessageID];
    
    //Locale
    GDataXMLElement *Locale=[GDataXMLElement elementWithName:@"Locale" URI:xmlns_w.stringValue];
    GDataXMLNode *lang=[GDataXMLNode attributeWithName:@"xml:lang" stringValue:@"en-US"];
    [Locale addAttribute:lang];
    GDataXMLNode *mustUnderstandFalse=[GDataXMLNode attributeWithName:@"mustUnderstand" URI:xmlns_s.stringValue stringValue:@"false"];
    [Locale addAttribute:mustUnderstandFalse];
    [header addChild:Locale];
    
    GDataXMLElement *DataLocale=[GDataXMLElement elementWithName:@"DataLocale" URI:xmlns_p.stringValue];
    //lang
    [DataLocale addAttribute:lang];
    //mustunderstand
    [DataLocale addAttribute:mustUnderstandFalse];
    [header addChild:DataLocale];
    
    //SelectorSet
    GDataXMLElement *SelectorSet=[GDataXMLElement elementWithName:@"SelectorSet" URI:xmlns_w.stringValue];
    
    [SelectorSet addNamespace:xmlns_w];
    GDataXMLNode *wsman=[GDataXMLNode attributeWithName:@"xmlns" stringValue:xmlns_w.stringValue];
    [SelectorSet addAttribute:wsman];
    
    GDataXMLElement *Selector=[GDataXMLElement elementWithName:@"Selector" URI:xmlns_w.stringValue];
    GDataXMLNode *ShellIdAttr=[GDataXMLNode attributeWithName:@"Name" stringValue:@"ShellId"];
    [Selector addAttribute:ShellIdAttr];
    [Selector setStringValue:shellid];
    [SelectorSet addChild:Selector];
    [header addChild:SelectorSet];
    
    //OperationTimeout
    GDataXMLElement *OperationTimeout=[GDataXMLElement elementWithName:@"OperationTimeout" URI:xmlns_w.stringValue];
    [OperationTimeout setStringValue:@"PT60.000S"];
    [header addChild:OperationTimeout];
    
    //NSLog(@"%@",header);
    
    return header;
    
}

-(GDataXMLElement*)xmlEnvelopeDeleteBody{
    
    GDataXMLElement *body=[GDataXMLElement elementWithName:@"Body" URI:xmlns_s.stringValue];
    [body setStringValue:@""];
    
    return body;
}





@end
