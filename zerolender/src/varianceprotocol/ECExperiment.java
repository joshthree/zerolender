package varianceprotocol;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;

public class ECExperiment {
	
	public static int[] trials = {1000/*, 100, 1000, 10000, 100000, 200000, 300000, 400000, 500000, 1000000, 2000000, 10000000/*,100,1000,10000, 1000000, 2000000, 10000000/*, 3000000, 5000000, 7000000, 9000000*/};
	//java -cp "./jars/bcprov-ext-jdk15on-157.jar;./bin" protocol.ECExperiment 54321 1p

	public static void main(String[] args) throws Exception
	{
		System.out.println("Set Java to high priotiry then press enter.");
		System.in.read();
		//<ip> <port> <accounts file name> <key file name> <environment file name> <blockSize> [seed (optional)]
		String[] mainInputs = new String[7];
		mainInputs[0] = "127.0.0.1";
		mainInputs[1] = "12345";
		mainInputs[4] = "ecEnvironment";
		mainInputs[5] = "1";
		mainInputs[6] = args[0];
		
		
		// <curve name> <numKeys> <ProportionOfOwnedKeys> <ProportionOfOwnedKeysOwnedByP1> [Seed]
		
		String p1 = "0.05";
		String p2 = "0.5";
		String party = "P2Keys";
		if(args[1].equals("1p"))
		{
			party = "P1Keys";
			String[] keyMakerInputs = new String[7];

			InputStream envFile = new FileInputStream("ecEnvironment");
		    InputStreamReader isr3 = new InputStreamReader(envFile);
		    BufferedReader envBr = new BufferedReader(isr3);
		    String dataRow;
			dataRow = envBr.readLine();
			String[] envString = dataRow.split("\t");
			System.out.println(envString[0]);
			keyMakerInputs[0] = envString[0];
			envBr.close();
			keyMakerInputs[2] = p1;
			keyMakerInputs[3] = p2;
			keyMakerInputs[4] = "0";
			
			for(int t : trials)
			{
				keyMakerInputs[1] = t + "";
				ECKeyMaker.main(keyMakerInputs);
				keyMakerInputs[4] = keyMakerInputs[1];
			}
		}
		if(args[1].equals("1")) party = "P1Keys";
		for(int t : trials)
		{
			System.out.flush();
			mainInputs[2] = "Account" + t + "_" + p1 + "_" + p2;
			mainInputs[3] = party + t + "_" + p1 + "_" + p2;
			System.out.print("Protocol ");
			for(String s : mainInputs)
				System.out.print(s + " ");
			System.out.println();
			System.out.println("\tProvisions:");
			ProtocolMainECMixedMalProvisions.main(mainInputs);
			System.out.println("\tVariance:");
			ProtocolMainECMixedMalWithComparison.main(mainInputs);
			
		}
	}
}
