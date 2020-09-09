# DezerializationForDummies
Some interesting qoutes and comments regarding to deserialization in JAVA.

## What the Fu*k is going on?

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
