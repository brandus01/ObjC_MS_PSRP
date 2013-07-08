//
//  MS-PSRP.m
//  powershell
//
//  Created by Joshua Langford on 8/22/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//
// MS-PSRP 2.2.1 & Message Bytes & 2.2.4 Packet Fragments

/*
 1-8 ObjectId
 9-16 FragmentId
 17 Fragment Order
 18-21 BlobLength
 22-25 Destination
 26-29 MessageType
 30-45 RPID
 46-61 PID
 62-64 BOM
*/

#import "MS-PSRP.h"

#import "GDataXMLNode.h"

@implementation MS_PSRP

@synthesize destServer;
@synthesize destClient;
@synthesize pid0;
@synthesize bom;
@synthesize objectID;
@synthesize fragmentID;
//@synthesize fragmentOrder;

@synthesize fragment_Middle;
@synthesize fragment_End;
@synthesize fragment_Start;
@synthesize fragment_StartAndEnd;

@synthesize msgType_SESSION_CAPABILITY;
@synthesize msgType_INIT_RUNSPACEPOOL;
@synthesize msgType_APPLICATION_PRIVATE_DATA;
@synthesize msgType_RUNSPACEPOOL_STATE;
@synthesize msgType_CREATE_PIPELINE;
@synthesize msgType_PIPELINE_STATE;
@synthesize msgType_PIPELINE_INPUT;
@synthesize msgType_PIPELINE_OUTPUT;
@synthesize msgType_PIPELINE_HOST_CALL;
@synthesize msgType_PIPELINE_HOST_RESPONSE;
@synthesize msgType_ERROR_RECORD;
@synthesize msgType_GET_COMMAND_METADATA;

@synthesize RunspacePoolState_BeforeOpen;
@synthesize RunspacePoolState_Opening;
@synthesize RunspacePoolState_Opened;
@synthesize RunspacePoolState_Closed;
@synthesize RunspacePoolState_Closing;
@synthesize RunspacePoolState_Broken;
@synthesize RunspacePoolState_Connecting;
@synthesize RunspacePoolState_Disconnected;
@synthesize RunspacePoolState_NegotiationSent;
@synthesize RunspacePoolState_NegotiationSucceeded;

@synthesize PipelineState_Notstarted;
@synthesize PipelineState_Running;
@synthesize PipelineState_Stopping;
@synthesize PipelineState_Stopped;
@synthesize PipelineState_Completed;
@synthesize PipelineState_Failed;
@synthesize PipelineState_Disconnected;

-(id)init{
    if(self==[super init]){
        destClient=1;
        destServer=2;
        
        char pid0bytes[16]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        pid0=[NSData dataWithBytes:&pid0bytes length:16];
        char bombytes[3]={0xef, 0xbb, 0xbf};
        bom=[NSData dataWithBytes:bombytes length:3];
        
        objectID=CFSwapInt64HostToBig(30);
        fragmentID=CFSwapInt64HostToBig(0);
        //fragmentOrder=0x03;
        
        //2.2.4 Packet Fragment
        fragment_Middle=0;
        fragment_End=2;
        fragment_Start=1;
        fragment_StartAndEnd=3;        
        
        //MS-PSRP 2.2.1 2.2.1 PowerShell Remoting Protocol Message Types
        msgType_SESSION_CAPABILITY=0x00010002;
        msgType_INIT_RUNSPACEPOOL=0x00010004;
        msgType_APPLICATION_PRIVATE_DATA=0x00021009;
        msgType_RUNSPACEPOOL_STATE=0x00021005;
        msgType_CREATE_PIPELINE=0x00021006;
        msgType_PIPELINE_STATE=0x00041006;
        msgType_PIPELINE_INPUT=0x00041002;
        msgType_PIPELINE_OUTPUT=0x00041004;
        msgType_PIPELINE_HOST_CALL=0x00041100;
        msgType_PIPELINE_HOST_RESPONSE=0x00041101;
        msgType_ERROR_RECORD=0x00041005;
        msgType_GET_COMMAND_METADATA=0x0002100A;
        
        //MS-PSRP 2.2.3.4 RunspacePoolState
        RunspacePoolState_BeforeOpen=0;
        RunspacePoolState_Opening=1;
        RunspacePoolState_Opened=2;
        RunspacePoolState_Closed=3;
        RunspacePoolState_Closing=4;
        RunspacePoolState_Broken=5;
        RunspacePoolState_NegotiationSent=6;
        RunspacePoolState_NegotiationSucceeded=7;
        RunspacePoolState_Connecting=8;
        RunspacePoolState_Disconnected=9;
        
        //MS-PSRP 2.2.3.5 PSInvocationState
        PipelineState_Notstarted=0;
        PipelineState_Running=1;
        PipelineState_Stopping=2;
        PipelineState_Stopped=3;
        PipelineState_Completed=4;
        PipelineState_Failed=5;
        PipelineState_Disconnected=6;
    }
    
    return self;
}

-(uint64_t)increment:(uint64_t)bigint{
    uint64_t little=CFSwapInt64BigToHost(bigint);
    little++;
    
    return CFSwapInt64HostToBig(little);
}

#pragma mark serializing

-(NSString*)serializeString:(NSString*)string{
    //MS-PSRP 2.2.5.3.2 Encoding Strings
    string=[string stringByReplacingOccurrencesOfString:@"\n" withString:@"_x000D_"];
    string=[string stringByReplacingOccurrencesOfString:@"\r" withString:@"_x000A_"];
    string=[string stringByReplacingOccurrencesOfString:@"\t" withString:@"_x0009_"];
    return string;
}

-(NSMutableData*)xml_NewShellWithRPID:(NSString*)rpid{
    
    NSLog(@"object id: %@",[[NSData dataWithBytes:&objectID length:sizeof(objectID)] description]);
    
    NSMutableData *creationXml=[NSMutableData dataWithBytes:&objectID length:8];
    objectID=[self increment:objectID];
    [creationXml appendBytes:&fragmentID length:8];
    [creationXml appendBytes:&fragment_StartAndEnd length:1];
    
    //SESSION CAPABILITY
    
    NSMutableData *fragment_SESSION_CAPABILITY=[NSMutableData dataWithBytes:&destServer length:4];
    [fragment_SESSION_CAPABILITY appendBytes:&msgType_SESSION_CAPABILITY length:4];
    [fragment_SESSION_CAPABILITY appendBytes:[rpid dataUsingEncoding:NSUTF8StringEncoding].bytes length:16];
    [fragment_SESSION_CAPABILITY appendBytes:pid0.bytes length:16];
    [fragment_SESSION_CAPABILITY appendBytes:bom.bytes length:3];
    NSData *data_SESSION_CAPABILITY=[[self xml_SESSION_CAPABILITY] dataUsingEncoding:NSUTF8StringEncoding];
    [fragment_SESSION_CAPABILITY appendBytes:data_SESSION_CAPABILITY.bytes length:data_SESSION_CAPABILITY.length];
    
    uint32_t fragment_SESSION_CAPABILITY_length=CFSwapInt32HostToBig(fragment_SESSION_CAPABILITY.length);
    [creationXml appendBytes:&fragment_SESSION_CAPABILITY_length length:4];
    [creationXml appendBytes:fragment_SESSION_CAPABILITY.bytes length:fragment_SESSION_CAPABILITY.length];
    
    //INIT RUNSPACEPOOL
    [creationXml appendBytes:&objectID length:8];
    objectID=[self increment:objectID];
    [creationXml appendBytes:&fragmentID length:8];
    [creationXml appendBytes:&fragment_StartAndEnd length:1];
    
    NSMutableData *fragment_INIT_RUNSPACEPOOL=[NSMutableData dataWithBytes:&destServer length:4];
    [fragment_INIT_RUNSPACEPOOL appendBytes:&msgType_INIT_RUNSPACEPOOL length:4];
    [fragment_INIT_RUNSPACEPOOL appendBytes:[rpid dataUsingEncoding:NSUTF8StringEncoding].bytes length:16];
    [fragment_INIT_RUNSPACEPOOL appendBytes:pid0.bytes length:16];
    [fragment_INIT_RUNSPACEPOOL appendBytes:bom.bytes length:3];
    NSData *data_INIT_RUNSPACEPOOL=[[self xml_INIT_RUNSPACEPOOL] dataUsingEncoding:NSUTF8StringEncoding];
    [fragment_INIT_RUNSPACEPOOL appendBytes:data_INIT_RUNSPACEPOOL.bytes length:data_INIT_RUNSPACEPOOL.length];
    
    uint32_t fragment_INIT_RUNSPACEPOOL_length=CFSwapInt32HostToBig(fragment_INIT_RUNSPACEPOOL.length);
    [creationXml appendBytes:&fragment_INIT_RUNSPACEPOOL_length length:4];
    [creationXml appendBytes:fragment_INIT_RUNSPACEPOOL.bytes length:fragment_INIT_RUNSPACEPOOL.length];
    
    return creationXml;
}

-(NSString*)xml_SESSION_CAPABILITY{
    NSString *SESSION_CAPABILITY=[NSMutableString stringWithFormat:@"<Obj RefId=\"0\"><MS><Version N=\"protocolversion\">2.1</Version><Version N=\"PSVersion\">2.0</Version><Version N=\"SerializationVersion\">1.1.0.1</Version></MS></Obj>"];
    
    return SESSION_CAPABILITY;
}

-(NSString*)xml_INIT_RUNSPACEPOOL{
    
    NSString *INIT_RUNSPACEPOOL=[NSString stringWithFormat:@"<Obj RefId=\"0\"><MS><I32 N=\"MinRunspaces\">1</I32><I32 N=\"MaxRunspaces\">1</I32><Obj N=\"PSThreadOptions\" RefId=\"1\"><TN RefId=\"0\"><T>System.Management.Automation.Runspaces.PSThreadOptions</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Default</ToString><I32>0</I32></Obj><Obj N=\"ApartmentState\" RefId=\"2\"><TN RefId=\"1\"><T>System.Threading.ApartmentState</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Unknown</ToString><I32>2</I32></Obj><Obj N=\"ApplicationArguments\" RefId=\"3\"><TN RefId=\"2\"><T>System.Management.Automation.PSPrimitiveDictionary</T><T>System.Collections.Hashtable</T><T>System.Object</T></TN><DCT><En><S N=\"Key\">PSVersionTable</S><Obj N=\"Value\" RefId=\"4\"><TNRef RefId=\"2\" /><DCT><En><S N=\"Key\">CLRVersion</S><Version N=\"Value\">2.0.50727.5456</Version></En><En><S N=\"Key\">BuildVersion</S><Version N=\"Value\">6.1.7601.17514</Version></En><En><S N=\"Key\">PSVersion</S><Version N=\"Value\">2.0</Version></En><En><S N=\"Key\">WSManStackVersion</S><Version N=\"Value\">2.0</Version></En><En><S N=\"Key\">PSCompatibleVersions</S><Obj N=\"Value\" RefId=\"5\"><TN RefId=\"3\"><T>System.Version[]</T><T>System.Array</T><T>System.Object</T></TN><LST><Version>1.0</Version><Version>2.0</Version></LST></Obj></En><En><S N=\"Key\">SerializationVersion</S><Version N=\"Value\">1.1.0.1</Version></En><En><S N=\"Key\">PSRemotingProtocolVersion</S><Version N=\"Value\">2.1</Version></En></DCT></Obj></En></DCT></Obj><Obj N=\"HostInfo\" RefId=\"6\"><MS><Obj N=\"_hostDefaultData\" RefId=\"7\"><MS><Obj N=\"data\" RefId=\"8\"><TN RefId=\"4\"><T>System.Collections.Hashtable</T><T>System.Object</T></TN><DCT><En><I32 N=\"Key\">9</I32><Obj N=\"Value\" RefId=\"9\"><MS><S N=\"T\">System.String</S><S N=\"V\">Administrator: Windows PowerShell</S></MS></Obj></En><En><I32 N=\"Key\">8</I32><Obj N=\"Value\" RefId=\"10\"><MS><S N=\"T\">System.Management.Automation.Host.Size</S><Obj N=\"V\" RefId=\"11\"><MS><I32 N=\"width\">160</I32><I32 N=\"height\">58</I32></MS></Obj></MS></Obj></En><En><I32 N=\"Key\">7</I32><Obj N=\"Value\" RefId=\"12\"><MS><S N=\"T\">System.Management.Automation.Host.Size</S><Obj N=\"V\" RefId=\"13\"><MS><I32 N=\"width\">160</I32><I32 N=\"height\">58</I32></MS></Obj></MS></Obj></En><En><I32 N=\"Key\">6</I32><Obj N=\"Value\" RefId=\"14\"><MS><S N=\"T\">System.Management.Automation.Host.Size</S><Obj N=\"V\" RefId=\"15\"><MS><I32 N=\"width\">154</I32><I32 N=\"height\">28</I32></MS></Obj></MS></Obj></En><En><I32 N=\"Key\">5</I32><Obj N=\"Value\" RefId=\"16\"><MS><S N=\"T\">System.Management.Automation.Host.Size</S><Obj N=\"V\" RefId=\"17\"><MS><I32 N=\"width\">160</I32><I32 N=\"height\">3000</I32></MS></Obj></MS></Obj></En><En><I32 N=\"Key\">4</I32><Obj N=\"Value\" RefId=\"18\"><MS><S N=\"T\">System.Int32</S><I32 N=\"V\">25</I32></MS></Obj></En><En><I32 N=\"Key\">3</I32><Obj N=\"Value\" RefId=\"19\"><MS><S N=\"T\">System.Management.Automation.Host.Coordinates</S><Obj N=\"V\" RefId=\"20\"><MS><I32 N=\"x\">0</I32><I32 N=\"y\">178</I32></MS></Obj></MS></Obj></En><En><I32 N=\"Key\">2</I32><Obj N=\"Value\" RefId=\"21\"><MS><S N=\"T\">System.Management.Automation.Host.Coordinates</S><Obj N=\"V\" RefId=\"22\"><MS><I32 N=\"x\">0</I32><I32 N=\"y\">205</I32></MS></Obj></MS></Obj></En><En><I32 N=\"Key\">1</I32><Obj N=\"Value\" RefId=\"23\"><MS><S N=\"T\">System.ConsoleColor</S><I32 N=\"V\">5</I32></MS></Obj></En><En><I32 N=\"Key\">0</I32><Obj N=\"Value\" RefId=\"24\"><MS><S N=\"T\">System.ConsoleColor</S><I32 N=\"V\">6</I32></MS></Obj></En></DCT></Obj></MS></Obj><B N=\"_isHostNull\">false</B><B N=\"_isHostUINull\">false</B><B N=\"_isHostRawUINull\">false</B><B N=\"_useRunspaceHost\">false</B></MS></Obj></MS></Obj>"];
    
    return INIT_RUNSPACEPOOL;
}

-(NSMutableData*)xml_CREATE_PIPELINEwithRPID:(NSString*)rpid PID:(NSString*)pid UnicodeScript:(NSString*)unicodescript{
    
    NSString *UnicodeScript=unicodescript;
    
    if(UnicodeScript==nil){
        UnicodeScript=[NSString stringWithFormat:@""];
    }
    else{
        UnicodeScript=[self serializeString:UnicodeScript];
    }
    
    /*
    if([UnicodeScript length]>2000){
        UnicodeScript=[UnicodeScript substringToIndex:2000];
    }
    */
    
    NSMutableString *CREATE_PIPELINE=[NSMutableString stringWithFormat:@"<Obj RefId=\"0\"><MS><Obj N=\"PowerShell\" RefId=\"1\"><MS><Obj N=\"Cmds\" RefId=\"2\"><TN RefId=\"0\"><T>System.Collections.Generic.List`1[[System.Management.Automation.PSObject, System.Management.Automation, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]]</T><T>System.Object</T></TN><LST><Obj RefId=\"3\"><MS><S N=\"Cmd\">"];
    [CREATE_PIPELINE appendString:UnicodeScript];
    [CREATE_PIPELINE appendString:@"</S><B N=\"IsScript\">true</B><Nil N=\"UseLocalScope\" /><Obj N=\"MergeMyResult\" RefId=\"4\"><TN RefId=\"1\"><T>System.Management.Automation.Runspaces.PipelineResultTypes</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>None</ToString><I32>0</I32></Obj><Obj N=\"MergeToResult\" RefId=\"5\"><TNRef RefId=\"1\" /><ToString>None</ToString><I32>0</I32></Obj><Obj N=\"MergePreviousResults\" RefId=\"6\"><TNRef RefId=\"1\" /><ToString>None</ToString><I32>0</I32></Obj><Obj N=\"Args\" RefId=\"7\"><TNRef RefId=\"0\" /><LST /></Obj></MS></Obj></LST></Obj><B N=\"IsNested\">false</B><Nil N=\"History\" /><B N=\"RedirectShellErrorOutputPipe\">true</B></MS></Obj><B N=\"NoInput\">true</B><Obj N=\"ApartmentState\" RefId=\"8\"><TN RefId=\"2\"><T>System.Threading.ApartmentState</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Unknown</ToString><I32>2</I32></Obj><Obj N=\"RemoteStreamOptions\" RefId=\"9\"><TN RefId=\"3\"><T>System.Management.Automation.RemoteStreamOptions</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>0</ToString><I32>0</I32></Obj><B N=\"AddToHistory\">true</B><Obj N=\"HostInfo\" RefId=\"10\"><MS><B N=\"_isHostNull\">true</B><B N=\"_isHostUINull\">true</B><B N=\"_isHostRawUINull\">true</B><B N=\"_useRunspaceHost\">true</B></MS></Obj></MS></Obj>"];
    
    //NSLog(@"create_pipeline: %@",CREATE_PIPELINE);
    
    NSLog(@"object id: %@",[[NSData dataWithBytes:&objectID length:sizeof(objectID)] description]);
    
    NSMutableData *createpipelineXml=[NSMutableData dataWithBytes:&objectID length:8];
    objectID=[self increment:objectID];
    [createpipelineXml appendBytes:&fragmentID length:8];
    [createpipelineXml appendBytes:&fragment_StartAndEnd length:1];
    
    NSMutableData *fragment_CREATE_PIPELINE=[NSMutableData dataWithBytes:&destServer length:4];
    [fragment_CREATE_PIPELINE appendBytes:&msgType_CREATE_PIPELINE length:4];
    [fragment_CREATE_PIPELINE appendBytes:[rpid dataUsingEncoding:NSUTF8StringEncoding].bytes length:16];
    [fragment_CREATE_PIPELINE appendBytes:[pid dataUsingEncoding:NSUTF8StringEncoding].bytes length:16];
    [fragment_CREATE_PIPELINE appendBytes:bom.bytes length:3];
    NSData *data_CREATE_PIPELINE=[CREATE_PIPELINE dataUsingEncoding:NSUTF8StringEncoding];
    [fragment_CREATE_PIPELINE appendBytes:data_CREATE_PIPELINE.bytes length:data_CREATE_PIPELINE.length];
    
    uint32_t fragment_CREATE_PIPELINE_length=CFSwapInt32HostToBig(fragment_CREATE_PIPELINE.length);
    [createpipelineXml appendBytes:&fragment_CREATE_PIPELINE_length length:4];
    [createpipelineXml appendBytes:fragment_CREATE_PIPELINE.bytes length:fragment_CREATE_PIPELINE.length];
    
    return createpipelineXml;
}

-(NSData*)xml_PIPELINE_HOST_RESPONSEwithRPID:(NSString *)rpid PID:(NSString *)pid Key:(NSString *)key Value:(NSString*)value{
    
    if(key==nil){key=@"";}
    if(value==nil){value=@"";}
    
    NSMutableString *PIPELINE_HOST_RESPONSE=[NSMutableString stringWithFormat:@"<Obj RefId=\"0\"><MS><Obj N=\"mr\" RefId=\"1\"><TN RefId=\"0\"><T>System.Collections.Hashtable</T><T>System.Object</T></TN><DCT><En><S N=\"Key\">"];
   [PIPELINE_HOST_RESPONSE appendString:key];
   [PIPELINE_HOST_RESPONSE appendString:@"</S><S N=\"Value\">"];
   [PIPELINE_HOST_RESPONSE appendString:value];
   [PIPELINE_HOST_RESPONSE appendString:@"</S></En></DCT></Obj><I64 N=\"ci\">1</I64><Obj N=\"mi\" RefId=\"2\"><TN RefId=\"1\"><T>System.Management.Automation.Remoting.RemoteHostMethodId</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Prompt</ToString><I32>23</I32></Obj></MS></Obj>"];
    
    NSLog(@"input: %@",PIPELINE_HOST_RESPONSE);
    
    NSLog(@"object id: %@",[[NSData dataWithBytes:&objectID length:sizeof(objectID)] description]);
    NSMutableData *PIPELINE_HOST_RESPONSEXml=[NSMutableData dataWithBytes:&objectID length:8];
    objectID=[self increment:objectID];
    [PIPELINE_HOST_RESPONSEXml appendBytes:&fragmentID length:8];
    [PIPELINE_HOST_RESPONSEXml appendBytes:&fragment_StartAndEnd length:1];
    
    NSMutableData *fragment_PIPELINE_HOST_RESPONSE=[NSMutableData dataWithBytes:&destServer length:4];
    [fragment_PIPELINE_HOST_RESPONSE appendBytes:&msgType_PIPELINE_HOST_RESPONSE length:4];
    [fragment_PIPELINE_HOST_RESPONSE appendBytes:[rpid dataUsingEncoding:NSUTF8StringEncoding].bytes length:16];
    [fragment_PIPELINE_HOST_RESPONSE appendBytes:[pid dataUsingEncoding:NSUTF8StringEncoding].bytes length:16];
    [fragment_PIPELINE_HOST_RESPONSE appendBytes:bom.bytes length:3];
    NSData *data_PIPELINE_HOST_RESPONSE=[PIPELINE_HOST_RESPONSE dataUsingEncoding:NSUTF8StringEncoding];
    [fragment_PIPELINE_HOST_RESPONSE appendBytes:data_PIPELINE_HOST_RESPONSE.bytes length:data_PIPELINE_HOST_RESPONSE.length];
    
    uint32_t fragment_PIPELINE_HOST_RESPONSE_length=CFSwapInt32HostToBig(fragment_PIPELINE_HOST_RESPONSE.length);
    [PIPELINE_HOST_RESPONSEXml appendBytes:&fragment_PIPELINE_HOST_RESPONSE_length length:4];
    [PIPELINE_HOST_RESPONSEXml appendBytes:fragment_PIPELINE_HOST_RESPONSE.bytes length:fragment_PIPELINE_HOST_RESPONSE.length];
    
    return PIPELINE_HOST_RESPONSEXml;
}

-(NSData*)xml_GET_COMMAND_METADATAwithRPID:(NSString *)rpid PID:(NSString *)pid{
    
    //MS-PSRP 2.2.2.14 GET_COMMAND_METADATA Message
    
    NSMutableString *GET_COMMAND_METADATA=[NSMutableString stringWithFormat:@"<Obj RefId=\"0\"><MS><Obj N=\"Name\" RefId=\"1\"><TN RefId=\"0\"><T>System.String[]</T><T>System.Array</T><T>System.Object</T></TN><LST><S>Out-Default</S><S>Exit-PSSession</S></LST></Obj><Obj N=\"CommandType\" RefId=\"2\"><TN RefId=\"1\"><T>System.Management.Automation.CommandTypes</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Alias, Function, Filter, Cmdlet</ToString><I32>15</I32></Obj><Nil N=\"Namespace\" /><Nil N=\"ArgumentList\" /></MS></Obj>"];
    
    NSLog(@"GET_COMMAND_METADATA: %@",GET_COMMAND_METADATA);
    
    NSMutableData *GET_COMMAND_METADATAXml=[NSMutableData dataWithBytes:&objectID length:8];
    objectID=[self increment:objectID];
    [GET_COMMAND_METADATAXml appendBytes:&fragmentID length:8];
    [GET_COMMAND_METADATAXml appendBytes:&fragment_StartAndEnd length:1];
    
    NSMutableData *fragment_GET_COMMAND_METADATA=[NSMutableData dataWithBytes:&destServer length:4];
    [fragment_GET_COMMAND_METADATA appendBytes:&msgType_GET_COMMAND_METADATA length:4];
    [fragment_GET_COMMAND_METADATA appendBytes:[rpid dataUsingEncoding:NSUTF8StringEncoding].bytes length:16];
    [fragment_GET_COMMAND_METADATA appendBytes:[pid dataUsingEncoding:NSUTF8StringEncoding].bytes length:16];
    [fragment_GET_COMMAND_METADATA appendBytes:bom.bytes length:3];
    NSData *data_GET_COMMAND_METADATA=[GET_COMMAND_METADATA dataUsingEncoding:NSUTF8StringEncoding];
    [fragment_GET_COMMAND_METADATA appendBytes:data_GET_COMMAND_METADATA.bytes length:data_GET_COMMAND_METADATA.length];
    
    uint32_t fragment_GET_COMMAND_METADATA_length=CFSwapInt32HostToBig(fragment_GET_COMMAND_METADATA.length);
    [GET_COMMAND_METADATAXml appendBytes:&fragment_GET_COMMAND_METADATA_length length:4];
    [GET_COMMAND_METADATAXml appendBytes:fragment_GET_COMMAND_METADATA.bytes length:fragment_GET_COMMAND_METADATA.length];
    
    return GET_COMMAND_METADATAXml;
}

#pragma mark parsing

-(NSString*)deserializeString:(NSString*)string{
    
    //MS-PSRP 2.2.5.3.2 Encoding Strings
    string=[string stringByReplacingOccurrencesOfString:@"_x000D_" withString:@"\n"];
    string=[string stringByReplacingOccurrencesOfString:@"_x000A_" withString:@"\r"];
    string=[string stringByReplacingOccurrencesOfString:@"_x0009_" withString:@"\t"];
    return string;
}

-(NSMutableDictionary*)parseOutputForObject:(GDataXMLDocument*)xml{
    

    //Keys of outputDict: Output, Method, Key (for prompts)
    NSMutableDictionary *outputDict=[[NSMutableDictionary alloc] init];
    [outputDict setValue:@"Write1" forKey:@"Method"];
    
    NSMutableString *output=[[NSMutableString alloc] initWithFormat:@""];
    [outputDict setValue:output forKey:@"Output"];
    
    

    //is it an object?
    NSArray *results=[xml nodesForXPath:@"Obj" error:nil];
    
    if([results count]==0){
        NSString *results=[[NSString alloc] initWithData:xml.XMLData encoding:NSUTF8StringEncoding];
        NSLog(@"result not an object: %@",results);
        
        NSArray *stringArray=[xml nodesForXPath:@"S" error:nil];
        if([stringArray count]>0){
            [output appendString:[(GDataXMLElement*)[stringArray objectAtIndex:0] stringValue]];
        }
        
        [outputDict setValue:output forKey:@"Output"];
        return outputDict;
    }
    
    GDataXMLElement *obj=[results objectAtIndex:0];
    
    NSLog(@"obj: %@",obj.XMLString);
    
    //object could be a simple string
    NSString *String;
    NSArray *stringArray=[obj nodesForXPath:@"S[1]" error:nil];
    
    if([stringArray count]>0){
        String=[(GDataXMLElement*)[stringArray objectAtIndex:0] stringValue];
        NSLog(@"String: %@",String);
        [output appendString:String];
        [outputDict setValue:output forKey:@"Output"];
        return outputDict;
    }
    
    //output could depend on type
    NSString *Type;
    
    NSArray *typeArray=[obj nodesForXPath:@"TN/T[1] | MS/Obj[@N='ExceptionAsErrorRecord']/TN/T[1]" error:nil];
    
    if([typeArray count]>0){
        Type=[(GDataXMLElement*)[typeArray objectAtIndex:0] stringValue];
        NSLog(@"Type: %@",Type);
    }
    
    //Error
    //send to error parser
    if([Type isEqualToString:@"System.Management.Automation.ErrorRecord"]){
        outputDict=[self parseErrorOutput:obj addToDict:outputDict];
        return outputDict;
    }
    
    //get-help
    //send to help parser to keep this parser short
    if([Type length] && [Type rangeOfString:@"MamlCommandHelpInfo"].location!=NSNotFound){
        NSLog(@"Get-Help Parsing");
        outputDict=[self parseGetHelpOutput:obj addToDict:outputDict];
        return outputDict;
    }
    
    //properties:
    NSArray *propsArray=[obj nodesForXPath:@"Props[1]" error:nil];
    if([propsArray count]>0){
        NSLog(@"props: %@",propsArray);
        GDataXMLElement *properties = [propsArray objectAtIndex:0];
        
        int maxLength=0;
        NSString *longest;
        
        for(GDataXMLElement *element in [properties children]){
            for(GDataXMLNode *attribute in element.attributes){
                if([attribute.stringValue length]>maxLength){
                    longest=attribute.stringValue;
                    maxLength=[longest length];
                }
            }
        }
        
        NSLog(@"longest parm: %@, length %d",longest,maxLength);
        
        for(GDataXMLElement *element in [properties children]){
            //NSLog(@"property: %@",element.name);
            
            NSString *elementType=element.name;
            
            //Objects may have multiple elements so stringValue would look bad
            //applies to System.Management.Automation.Internal.Host.InternalHost
            if([elementType isEqualToString:@"Obj"]){
                NSLog(@"object: %@",element.XMLString);
                for(GDataXMLNode *attribute in element.attributes){
                    
                    if([attribute.name isEqualToString:@"N"]){
                        NSLog(@"attribute name %@",attribute.stringValue);
                        [output appendString:attribute.stringValue];
                        [output appendString:@" : "];
                    }
                    break;
                }
                
                NSArray *nameArray=[element nodesForXPath:@"ToString" error:nil];
                
                NSLog(@"children: %@",nameArray);
                if([nameArray count]>0){
                    NSString *nameString=[(GDataXMLNode*)[nameArray objectAtIndex:0] stringValue];
                    NSLog(@"name: %@",nameString);
                    [output appendString:nameString];
                    
                }
                [output appendString:@"\n"];
            }
            else{
                for(GDataXMLNode *attribute in element.attributes){
                    
                    NSLog(@"%@ : %@",attribute.stringValue,element.stringValue);
                    
                    [output appendString:attribute.stringValue];
                    
                    //Padding?
                    /*
                    for(int i=0;i<(maxLength-[attribute.stringValue length]);i++){
                        NSLog(@"%d",i);
                        [output appendString:@" "];
                    }
                    */
                    
                    [output appendString:@" : "];
                    [output appendString:element.stringValue];
                    [output appendString:@"\n"];
                }
            }
        }
    }
    
    [outputDict setValue:output forKey:@"Output"];
    
    //extended properties
    //send to extended parser to keep this parser short
    NSArray *xpArray=[obj nodesForXPath:@"MS[1]" error:nil];
    if([xpArray count]>0){
        GDataXMLElement *xproperties = [xpArray objectAtIndex:0];
        
        outputDict=[self parseExtendedProperties:xproperties ofType:Type addToDict:outputDict];
        //[output appendString:[self parseExtendedProperties:xproperties ofType:Type]];
    }
    
    //[outputDict setValue:output forKey:@"Output"];
    
    return outputDict;
}

-(NSMutableDictionary*)parseErrorOutput:(GDataXMLElement*)xerror addToDict:(NSMutableDictionary*)outputdict{
    
    NSMutableDictionary *outputDict=outputdict;
    NSMutableString *output=[[NSMutableString alloc] initWithFormat:@"%@",[outputDict objectForKey:@"Output"]];
    [output appendString:@"\n"];
    
    GDataXMLElement *obj=[[xerror nodesForXPath:@"/Obj | MS/Obj[@N='ExceptionAsErrorRecord']" error:nil] lastObject];
    
    //NSLog(@"error obj: %@",obj.XMLString);
    
    NSArray *errorArray=[obj nodesForXPath:@"ToString[1] | //S[@N='PositionMessage']" error:nil];
    
    for(int i=0;i<[errorArray count];i++){
        
        GDataXMLElement *element=[errorArray objectAtIndex:i];
        
        NSLog(@"error element: %@",element.XMLString);
        
        NSString *scrubbed=[self deserializeString:element.stringValue];
        
        [output appendString:scrubbed];
        [output appendString:@"\n"];
    }
    
    
    
    [outputDict setValue:output forKey:@"Output"];
    return outputDict;
}

-(NSMutableDictionary*)parseGetHelpOutput:(GDataXMLElement*)xgethelp addToDict:(NSMutableDictionary*)outputdict{
    
    //NSLog(@"%@",xgethelp.XMLString);
    
    NSMutableDictionary *outputDict=outputdict;
    NSMutableString *output=[[NSMutableString alloc] initWithFormat:@"%@",[outputDict objectForKey:@"Output"]];
    [output appendString:@"\n"];
    
    NSArray *helpArray=[xgethelp nodesForXPath:@"MS/S[@N='Name'] | MS/S[@N='Synopsis']" error:nil];
    
    //NSLog(@"name: %@",helpArray);
    
    for(int i=0;i<[helpArray count];i++){
        GDataXMLElement *element=[helpArray objectAtIndex:i];
        NSArray *attributes=[element attributes];
        
        if([attributes count]>0){
            NSString *att=[(GDataXMLNode*)[attributes objectAtIndex:0] stringValue];
            [output appendString:[att uppercaseString]];
            [output appendString:@"\n    "];
        }
        
        [output appendString:[element stringValue]];
        [output appendString:@"\n\n"];
    }
    
    //description
    NSArray *descArray=[xgethelp nodesForXPath:@"Obj[TN/T='System.Management.Automation.PSCustomObject']/MS/Obj[@N='description']/LST/Obj/MS/S[@N='Text']" error:nil];
    
    //NSLog(@"Desc: %@",descArray);
    
    for(int i=0;i<[descArray count];i++){
        GDataXMLElement *element=[descArray objectAtIndex:i];

        [output appendString:@"DESCRIPTION\n    "];
        
        [output appendString:[element stringValue]];
        [output appendString:@"\n\n"];
    }
    
    //syntax
    NSArray *syntaxArray=[xgethelp nodesForXPath:@"Obj[TN/T='System.Management.Automation.PSCustomObject']/MS/Obj[@N='syntax']//MS[Obj[@N='parameter']]" error:nil];
    
    //NSLog(@"Syntax: %@",syntaxArray);
    [output appendString:[NSString stringWithFormat:@"SYNTAX"]];
    
    for(int i=0;i<[syntaxArray count];i++){
        
        GDataXMLElement *selement=[syntaxArray objectAtIndex:i];
        
        NSArray *snameArray=[selement nodesForXPath:@"S[@N='name']" error:nil];
        if([snameArray count]>0){
            [output appendString:@"\n    "];
            [output appendString:[(GDataXMLNode*)[snameArray objectAtIndex:0] stringValue]];
            [output appendString:@" "];
        }
        
        NSArray *paramArray=[selement nodesForXPath:@"Obj[@N='parameter']/LST/Obj" error:nil];
        for(GDataXMLElement *param in paramArray){
            
            
            NSArray *pnameArray=[param nodesForXPath:@"Obj/MS/S[@N='name']" error:nil];
            NSString *pname;
            
            if([pnameArray count]>0){
                pname=[(GDataXMLElement*)[pnameArray objectAtIndex:0] stringValue];
                [output appendString:@"[-"];
                [output appendString:pname];
            }
            
            NSArray *pvalueArray=[param nodesForXPath:@"Obj/MS/Obj[@N='parameterValue']/S" error:nil];
            NSString *pvalue;
            NSLog(@"pvalueArray: %@",pvalueArray);
            
            if([pvalueArray count]>0){
                pvalue=[(GDataXMLElement*)[pvalueArray objectAtIndex:0] stringValue];
                [output appendString:@" <"];
                [output appendString:pvalue];
                [output appendString:@">"];
            }
            
            [output appendString:@"] "];
            
        }//end params
        [output appendString:@"\n"];
    }//end syntax
    
    NSLog(@"output: %@",output);
    
    [outputDict setValue:output forKey:@"Output"];
    return outputDict;
}

-(NSMutableDictionary*)parseExtendedProperties:(GDataXMLElement*)xproperties ofType:(NSString*)type addToDict:(NSMutableDictionary*)outputdict{
    
    NSLog(@"extended properties: %@",xproperties.XMLString);
    
    NSMutableDictionary *outputDict=outputdict;
    NSMutableString *output=[[NSMutableString alloc] initWithFormat:@"%@",[outputDict objectForKey:@"Output"]];
    
    if([type isEqualToString:@"System.Management.Automation.PSDriveInfo"]){
        for(GDataXMLElement *element in [xproperties children]){
            NSLog(@"extended property: %@",element.name);
            
            for(GDataXMLNode *attribute in element.attributes){
                
                if([attribute.name isEqualToString:@"N"]){
                    NSLog(@"attribute name %@ (GB)",attribute.stringValue);
                    [output appendString:attribute.stringValue];
                    [output appendString:@" (GB)"];
                    [output appendString:@" : "];
                }
                break;
            }
            
            float gb=[element.stringValue floatValue];
            gb=gb/1024/1024/1024;
            [output appendString:[NSString stringWithFormat:@"%0.2f",gb]];
            [output appendString:@"\n"];
        }
    }
    else if([type isEqualToString:@"System.Management.Automation.ErrorRecord"]){
        
        NSArray *errorArray=[xproperties nodesForXPath:@"//Obj[@N='Exception']/Props/S[@N='Message']" error:nil];
        
        for(int i=0;i<[errorArray count];i++){
            [output appendString:[(GDataXMLElement*)[errorArray objectAtIndex:i] stringValue]];
            [output appendString:@"\n"];
        }
        
        [outputDict setValue:@"WriteErrorLine" forKey:@"Method"];
        [outputDict setValue:output forKey:@"Output"];
        
        return outputDict;
    }
    else if([type isEqualToString:@"Selected.Microsoft.PowerShell.Commands.GenericMeasureInfo"]){
        
        NSLog(@"Selected.Microsoft.PowerShell.Commands.GenericMeasureInfo");
        
    }
    else if(type==nil){
        //MS-PSRP 2.2.3.17 Host Method Identifier
        //find out what Method we're dealing with
        NSString *Type;
        NSArray *typeArray=[xproperties nodesForXPath:@"Obj[@N='mi']/TN/T[1]" error:nil];
        
        if([typeArray count]>0){
            Type=[(GDataXMLElement*)[typeArray objectAtIndex:0] stringValue];
            NSLog(@"Extended Type: %@",Type);
        }
        
        if([Type isEqualToString:@"System.Management.Automation.Remoting.RemoteHostMethodId"]){
            
            NSArray *methodArray=[xproperties nodesForXPath:@"Obj[@N='mi']/ToString" error:nil];
            NSString *method;
            
            if([methodArray count]>0){
                method=[(GDataXMLElement*)[methodArray objectAtIndex:0] stringValue];
                [outputDict setValue:method forKey:@"Method"];
                NSLog(@"Method: %@",method);
            }
            
            if([method isEqualToString:@"ReadLine"]){
                NSLog(@"ReadLine");
            }
            else if([method isEqualToString:@"ReadLineAsSecureString"]){
                NSLog(@"ReadLineAsSecureString");
            }
            else if([method isEqualToString:@"Write1"] || 
                    [method isEqualToString:@"Write2"] || 
                    [method isEqualToString:@"WriteLine1"] || 
                    [method isEqualToString:@"WriteLine2"] ||
                    [method isEqualToString:@"WriteLine3"] ||
                    [method isEqualToString:@"WriteErrorLine"] ||
                    [method isEqualToString:@"WriteDebugLine"] ||
                    [method isEqualToString:@"WriteProgress"] ||
                    [method isEqualToString:@"WriteVerboseLine"]
                    ){
                NSLog(@"Write");
                
                NSArray *outputArray=[xproperties nodesForXPath:@"Obj[@N='mp']//S[not(@*)]" error:nil];
                
                if([outputArray count]>0){
                    NSLog(@"outputArray: %@",outputArray);
                    
                    for(int i=0;i<[outputArray count];i++){
                        if(i>0){
                            if([[(GDataXMLElement*)[outputArray objectAtIndex:i] stringValue] length]>0){
                                [output appendString:@"\n"];
                            }
                        }
                        [output appendString:[(GDataXMLElement*)[outputArray objectAtIndex:i] stringValue]];
                    }

                    [outputDict setValue:output forKey:@"Output"];
                    return outputDict;
                }
            }

            else if([method isEqualToString:@"Prompt"]){
                NSLog(@"Prompt");
                
                //prompt output
                NSArray *promptArray=[xproperties nodesForXPath:@"Obj[@N='mp']//S[not(@*)]" error:nil];
                if([promptArray count]>0){
                    NSLog(@"promptArray: %@",promptArray);
                    
                    for(int i=0;i<[promptArray count];i++){
                        [output appendString:[(GDataXMLElement*)[promptArray objectAtIndex:i] stringValue]];
                        [output appendString:@"\n"];
                    }
                }
                
                //prompt key
                NSArray *keyArray=[xproperties nodesForXPath:@"Obj[@N='mp']//S[@N='name']" error:nil];
                if([keyArray count]>0){
                    NSLog(@"keyArray: %@",keyArray);
                    
                    NSString *key=[(GDataXMLElement*)[keyArray objectAtIndex:0] stringValue];
                    NSLog(@"key: %@",key);
                    [outputDict setValue:key forKey:@"Key"];
                    [output appendString:key];
                }
                
                [output appendString:@": "];
                [outputDict setValue:output forKey:@"Output"];
                return outputDict;
            }
            else if([method isEqualToString:@"PromptForCredential1"]){
                NSLog(@"PromptForCredential1");
            }
            else if([method isEqualToString:@"PromptForCredential1"]){
                NSLog(@"PromptForCredential1");
            }
            else if([method isEqualToString:@"PromptForCredential2"]){
                NSLog(@"PromptForCredential2");
            }
            else if([method isEqualToString:@"PromptForChoice"]){
                NSLog(@"PromptForChoice");
            }
            
        }
        else{
            NSLog(@"Unknown Type");
            [output appendString:[NSString stringWithFormat:@"%@",xproperties.stringValue]];
            [outputDict setValue:output forKey:@"Output"];
        }
    }
    else{
        NSLog(@"Unhandled Object Type");
        [output appendString:[NSString stringWithFormat:@"%@",xproperties.stringValue]];
        [outputDict setValue:output forKey:@"Output"];
    }
    
    
    [outputDict setValue:output forKey:@"Output"];
    return outputDict;
}

@end
