package net.zwerks.dumpfs;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;


public class DumpReceiver implements Runnable {
	
	private ServerSocket serverSock;
	private Socket connectedSock;
    private int serverPort;
    private String OutputPath;
    private String outputFilename;
    private String HDFSOutputPath;
    //private InputStream inStream;
    private DumpFSStatistics currStats;
    private HashCreator myHashGen;

	public DumpReceiver(String FileDumpDir, String DumpFileName, int listenPort, DumpFSStatistics myStatsCollector){
		// TODO Auto-generated constructor stub
		this.OutputPath = FileDumpDir;				//Directory where incoming file is to be dumped
		this.outputFilename = DumpFileName;			//File name of incoming dump file
		//this.HDFSOutputPath = "/user/hadoop_user/IDA_ARCHIVE/";					//Hadoop HDFS Chosen Dump Directory
		this.serverPort = listenPort;
		this.connectedSock = null;
		//this.inStream = null;
		this.currStats = myStatsCollector;
		this.myHashGen = new HashCreator(this.OutputPath+this.outputFilename);
		
		System.out.println("**********************************************************");
		System.out.println("Dump Receiver Activated.");
		System.out.println("File output path: "+ this.OutputPath+this.outputFilename);
		System.out.println("**********************************************************");
		
		//InputStream is = null;
		//this.serverPort = listenPort;
		
	}

	//@Override
	public void run() {

		InputStream inStream = null;
		//while(true){
		System.out.println("Attempting to receive compressed file ...");
			if(this.connectedSock == null){
				try{
					//ServerSocket servSock = new ServerSocket(serverPort);
					//Socket socket = servSock.accept();
					//this.serverSock = new ServerSocket(this.serverPort);
					//this.connectedSock = serverSock.accept();
					
					Socket myConnectedSock = new Socket("127.0.0.1", this.serverPort);
					
					inStream = myConnectedSock.getInputStream();
					
					this.connectedSock = myConnectedSock;
					
				} catch(IOException ioex){
					System.out.println("Caught I/O Exception while connecting: "+ioex);
					ioex.printStackTrace();
					//wait(0);
					//System.exit(0);
				}
			}
			
			long startCopyTime = System.currentTimeMillis();
			this.currStats.setFileTransStartTime(startCopyTime);
			
			byte[] aByte = new byte[1];
	        int bytesRead;
			
	        ByteArrayOutputStream baos = new ByteArrayOutputStream();
	               
	        if (inStream != null) {
	        	FileOutputStream fos = null;
	            BufferedOutputStream bos = null;
	        	
	        	System.out.println("Connected on: "+ this.connectedSock.getLocalAddress()+":"+this.connectedSock.getLocalPort());
	        	System.out.println("Receiving file from: "+ this.connectedSock.getInetAddress()+":"+this.connectedSock.getPort());
	            
	            try {
	            		            	
	                fos = new FileOutputStream( this.OutputPath + this.outputFilename );
	                System.out.println("------------------------------------------------");
	                System.out.println("Beginning File-write to disk ...");
	                System.out.println("------------------------------------------------");
	                System.out.println("Path to write file to: " + this.OutputPath + this.outputFilename);
	                                
	                bos = new BufferedOutputStream(fos);

	                //System.out.println("Preparing to write: " + aByte.length); ////<<<------------- to be commented out
	                // inputstream.read blocks until input data is available
	                bytesRead = inStream.read(aByte, 0, aByte.length);
	                
	                //System.out.println("Bytes Read : " + bytesRead); ////<<<------------- to be commented out
	                
	                System.out.println("Incoming Bytes available: " + inStream.available());
	                System.out.println("Preparing to write " + inStream.available() + " bytes ...");

	                double byteCounter = 0;
	                int stepCounter = 0;
	                int stepCounterRound = 0;
	                
	                System.out.print("#");
	                do {
	                        baos.write(aByte);
	                        bytesRead = inStream.read(aByte);
	                                                
	                        //Some sort of feedback that stuff is happening
	                        byteCounter++;
	                        //stepCounter = (int)byteCounter/1000;					//Truncates
	                        //stepCounterRound = (int)Math.round(byteCounter/1000);	//Rounds up or down >>> Difference at the "Step" points == 1
	                        //At every instance of divisibility print a "dot" i.e. print a dot for every MB approximately
	                        if(byteCounter % 1000000 == 0){		
	                        	System.out.print(".");
	                        	if ((byteCounter/1000000) % 2 == 0){
	                        		int my50Counter = (int)byteCounter/1000000;
	                        		System.out.print(my50Counter);
	                        		//System.out.print(bytesRead);
	                        		if(my50Counter % 50 == 0){
	                        			System.out.println("|");
	                        		}
	                        	}
	                        }
	                        
	                } while (bytesRead != -1);
	                //System.out.println("\n");
	                
	                bos.write(baos.toByteArray());
	                
	                //System.out.println("Transfer complete");
	                
	                bos.flush();
	                bos.close();
	                                
	                //fos.
	                fos.close();
	                inStream.close();
	                
	                System.out.println("Transfer complete");
	                
	                connectedSock.close();
	                
	            } catch (IOException ex) {
	            	System.out.println("Caught I/O Exception transferring file: "+ex);
					System.out.println("IO Error while getting HDFS URI");
					ex.printStackTrace();
				}
		}
		//}
	        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        	System.out.println("+++++++++++++++++++++++++++ FILE HASHES ++++++++++++++++++++++++++++++");
        	System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	        
        	System.out.println("MD5 hash: " + this.myHashGen.generateHash("MD5"));
        	System.out.println("SHA1 hash: " + this.myHashGen.generateHash("SHA1"));
	        
	        
	        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        	System.out.println("+++++++++++++++++++++++++++ RUN STATISTICS +++++++++++++++++++++++++++");
        	System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	        
	        //Stuff to output the time taken for the File Transfer transaction to complete
	        long finishCopyTime = System.currentTimeMillis();
	        this.currStats.setFileTransEndTime(finishCopyTime);
	            
	        System.out.println("File transfer time: " + this.currStats.convertLongToStringTime(this.currStats.getFileTransTime()));
		
	        long progEndTime = System.currentTimeMillis();
	        this.currStats.setAppEndTime(progEndTime);
	        
	        System.out.println("Total Application run time: " + this.currStats.convertLongToStringTime(this.currStats.getAppRunTime()));
	}
	
	public void listen(){

		
	}



}
