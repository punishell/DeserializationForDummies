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

![cyrus](https://raw.githubusercontent.com/punishell/DezerializationForDummies/master/cyrus.png)

So whats now? Go and test new knowledge here:

[the lab](https://github.com/NickstaDB/DeserLab).

























### Links
https://nickbloor.co.uk/2017/08/13/attacking-java-deserialization/

https://github.com/NickstaDB/SerializationDumper

https://docs.oracle.com/javase/7/docs/api/java/io/Serializable.html

https://juejin.im/entry/6844903501353451534

http://randomlinuxtech.blogspot.com/2017/08/java-deserialization-howto.html

https://blog.csdn.net/qsort_/article/details/104874111

https://blog.csdn.net/qsort_/article/details/104969138

https://meteatamel.wordpress.com/2012/02/13/jmx-rmi-vs-jmxmp/

https://github.com/frohoff/ysoserial/

