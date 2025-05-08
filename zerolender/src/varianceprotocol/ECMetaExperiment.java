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

public class ECMetaExperiment {
	
	
	public static void main(String[] args) throws Exception
	{
		String[] mainInputs = new String[3];
		mainInputs[0] = args[0];
		mainInputs[1] = args[1];
		long startTime, endTime;
		long[] time = new long[99];
		for(int i = 1; i < 100; i++)
		{
			mainInputs[2] = i + "";
			startTime = System.currentTimeMillis();
			for(int j = 0; j < 5; j++)
			{
				ECExperiment.main(mainInputs);
			}
			endTime = System.currentTimeMillis();
			time[i-1] = (endTime - startTime)/5;
			System.out.println(i + ":\t\t" + time[i-1] + "************************************************************************");
		}
		for(int i = 1; i < 100; i++)
		{
			System.out.println(i + ":\t\t" + time[i-1]);
		}
	}
}
