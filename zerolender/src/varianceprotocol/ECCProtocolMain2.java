package varianceprotocol;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import zero_knowledge_proofs.InvalidStringFormatException;

public class ECCProtocolMain2 {
	//TODO Make usage statement:  <excecutable> <ip> <port> <accounts file name> <key file name> <environment file name> [seed (optional)]
	@SuppressWarnings({ "resource" })
	public static void main(String[] args) 
	{
		final long startTime = System.currentTimeMillis();
		try {
			ProtocolMainMixed.main(args);		//This only exists to have different command line arguments and distinguish the parties in Eclipse.
		}
		catch(Exception e)
		{
			e.printStackTrace(System.err);
			System.err.flush();
			final long endTime = System.currentTimeMillis();
			System.out.printf(String.format("Total execution time before exception: %d\n", (endTime - startTime)));
		}
	}

}