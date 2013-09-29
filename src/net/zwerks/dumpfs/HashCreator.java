package net.zwerks.dumpfs;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/*
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.*;
import org.bouncycastle.crypto.digests.*;
*/

//import com.twmacinta.util.MD5;

/*
 * USING ONLY NATIVE JAVA CRYPTO API'S
 * NO BOUNCY CASTLE, FAST MD5, APACHE COMMONS DIGESTUTILS
 * */

public class HashCreator {

	private File myFile;
	private FileInputStream fis;
	
	public HashCreator(String FilePath) {
		// TODO Auto-generated constructor stub
		this.myFile = new File(FilePath);
		
				
	}
	/*
	public String getMD5Hash(){
		String hash = MD5.asHex(MD5.getHash(new File(filename)));		// <<<---- Using Fast-MD5 library
	}
	*/
	/*
	public String getMD5Hash(){
		//add the security provider
        //not required if you have Install the library
        //by Configuring the Java Runtime
        Security.addProvider(new BouncyCastleProvider());

        //this is the input;
        byte input[] = {0x00, 0x01, 0x02, 0x03, 0x04};
        //byte input[] = this.myFile.toString().getBytes();

        //update the input of MD5
        MD5Digest md5 = new MD5Digest();
        md5.update(input, 0, input.length);

        //get the output/ digest size and hash it
        byte[] digest = new byte[md5.getDigestSize()];
        md5.doFinal(digest, 0);

        //show the input and output
        //System.out.println("Input (hex): " + new String(Hex.encode(input)));
        //System.out.println("Output (hex): " + new String(Hex.encode(digest)));
        return new String(Hex.encode(digest));
	}
	*/
	public String generateHash(String myHashType){
		//HashType is ---> "MD5", "SHA1", "SHA256"
		try {
			this.fis = new FileInputStream(this.myFile);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			System.out.println("Error (File not found): " + e.getMessage());
			e.printStackTrace();
		}
		
		FileInputStream inputStream = this.fis;
		
		if(inputStream==null){

	        return null;
	    }
	    MessageDigest md;
	    try {
	        md = MessageDigest.getInstance(myHashType);  // <<<---- myHashType = "MD5" "SHA1" or "SHA256"
	        FileChannel channel = inputStream.getChannel();
	        ByteBuffer buff = ByteBuffer.allocate(2048);
	        
	        while(channel.read(buff) != -1){
	            buff.flip();
	            md.update(buff);
	            buff.clear();
	        }
	        byte[] hashValue = md.digest();
	        
	        //return new String(hashValue);
	        return this.toHex(hashValue);
	    }
	    catch (NoSuchAlgorithmException e){
	        return null;
	    } 
	    catch (IOException e){
	        return null;
	    }
	    finally{
	        try {
	            if(inputStream!=null)inputStream.close();
	        } catch (IOException e) {

	        }
	    } 
	}
	
	public static String toHex(byte[] bytes) {
	    BigInteger bi = new BigInteger(1, bytes);
	    return String.format("%0" + (bytes.length << 1) + "X", bi);
	}
	
}
