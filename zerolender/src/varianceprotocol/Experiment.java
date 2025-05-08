package varianceprotocol;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;

public class Experiment {
	
	public static int[] trials = {1000/*, 100, 1000, 10000, 100000, 200000, 300000,  400000, 500000/*, 1000000, 2000000, 4000000, 6000000, 8000000, 10000000, 3000000, 5000000, 7000000, 9000000*/};
	
	public static void main(String[] args) throws Exception
	{
		//<ip> <port> <accounts file name> <key file name> <environment file name> <blockSize> [seed (optional)]
		String[] mainInputs = new String[7];
		mainInputs[0] = "127.0.0.1";
		mainInputs[1] = "12345";
		mainInputs[4] = "environment.csv";
		mainInputs[5] = "1";
		mainInputs[6] = args[0];
		
		
		//<p> <g> <numKeys> <ProportionOfOwnedKeys> <ProportionOfOwnedKeysOwnedByP1> [Seed]
		File f = new File("./Key10_0.05_0.5");
		
		String p1 = "0.05";
		String p2 = "0.5";
		String party = "DLP2Keys";
		if(args[1].equals("1p"))
		{
			party = "DLP1Keys";
			String[] keyMakerInputs = new String[7];

			InputStream envFile = new FileInputStream("environment.csv");
		    InputStreamReader isr3 = new InputStreamReader(envFile);
		    BufferedReader envBr = new BufferedReader(isr3);
		    String dataRow;
			dataRow = envBr.readLine();
			String[] envString = dataRow.split("\t");
			keyMakerInputs[0] = envString[2];
			keyMakerInputs[1] = envString[0];
			keyMakerInputs[3] = p1;
			keyMakerInputs[4] = p2;
			keyMakerInputs[5] = "0";
			
			for(int t : trials)
			{
				keyMakerInputs[2] = t + "";
				KeyMaker.main(keyMakerInputs);
				keyMakerInputs[5] = keyMakerInputs[2];
			}
		}
		if(args[1].equals("1")) party = "DLP1Keys";
		for(int t : trials)
		{
			System.out.flush();
			mainInputs[2] = "DLAccount" + t + "_" + p1 + "_" + p2;
			mainInputs[3] = party + t + "_" + p1 + "_" + p2;
			System.out.print("Protocol ");
			for(String s : mainInputs)
				System.out.print(s + " ");
			System.out.println();

			ProtocolMainMixed.main(mainInputs);
			//ProtocolMainMixedProvisions.main(mainInputs);
			
			if(party.equals("DLP2Keys")) 
			{
				System.out.println("Waiting...");
				Thread.sleep(1000);
			}
		}
	}
}
