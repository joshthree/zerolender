package zero_knowledge_proofs;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;

import zero_knowledge_proofs.CryptoData.CryptoData;

public abstract class ZKPVerifier {
	private static ArrayList<VerifierProtocolPair> protocols = new ArrayList<VerifierProtocolPair>();
	private static ArrayList<VerifierProtocolPair> compoundProtocols = new ArrayList<VerifierProtocolPair>();

	@SuppressWarnings("rawtypes")
	public static boolean registerProtocol(String uniqueName, Class protocol, boolean isCompound)
	{
		for(VerifierProtocolPair ppp : protocols)
		{
			if(ppp.name.equals(uniqueName))
				return false;
		}
		VerifierProtocolPair vpp;
		try
		{
			vpp = new VerifierProtocolPair(uniqueName, protocol);
		}
		catch (ClassCastException e)
		{
			return false;
		}
		protocols.add(vpp);
		if(isCompound)
			compoundProtocols.add(vpp);
		return true;
	}
	
	public boolean verify(CryptoData input, BigInteger challenge, CryptoData environment, ObjectInputStream in, ObjectOutputStream out, StringBuilder transcriptOut) throws IOException, ClassNotFoundException
	{
		//System.out.println("vInput = " + input);
		CryptoData a = (CryptoData) in.readObject();
		out.writeObject(challenge);
		//System.out.println("vA = " + a);
		CryptoData z = (CryptoData) in.readObject();

		//System.out.println("vZ = " + z);
		boolean toReturn = verifyResponse(input, a, z, challenge, environment);
		out.writeObject(toReturn);
		if(transcriptOut != null)
		{
			transcriptOut.append("Input:  ");
			transcriptOut.append(input.toString64());
			transcriptOut.append("\nInitComm:  ");
			transcriptOut.append(a.toString64());
			transcriptOut.append("\nResponse:  ");
			transcriptOut.append(z.toString64());
	
			transcriptOut.append("\nchallenge:  ");
			transcriptOut.append(Base64.getEncoder().encodeToString(challenge.toByteArray()));
			transcriptOut.append("\nEnvironment:  ");
			transcriptOut.append(environment.toString64());
			transcriptOut.append("\n\n");
		}
		
		return toReturn;
	}
	public boolean maliciousVerify(CryptoData input, ECPedersenCommitment cCmt, BigInteger[] challenge, CryptoData environment, ObjectInputStream in, ObjectOutputStream out, StringBuilder transcriptOut) throws IOException, ClassNotFoundException
	{
		out.writeObject(cCmt);
		CryptoData a = (CryptoData) in.readObject();
		out.writeObject(challenge);
		boolean verified = (boolean) in.readObject();
		if(verified) {
			CryptoData z = (CryptoData) in.readObject();
			boolean toReturn = verifyResponse(input, a, z, challenge[0], environment);
			out.writeObject(toReturn);
			out.flush();
			if(transcriptOut != null)
			{
				transcriptOut.append("\nChallenge Commitment:  ");
				transcriptOut.append(cCmt.toString64());
				transcriptOut.append("\nInput:  ");
				transcriptOut.append(input.toString64());
				transcriptOut.append("\nInitComm:  ");
				transcriptOut.append(a.toString64());
				transcriptOut.append("\nResponse:  ");
				transcriptOut.append(z.toString64());
				transcriptOut.append("\nchallenge:  ");
				transcriptOut.append(Base64.getEncoder().encodeToString(challenge[0].toByteArray()));
				transcriptOut.append("\nchallenge key:  ");
				transcriptOut.append(Base64.getEncoder().encodeToString(challenge[1].toByteArray()));
	//			transcriptOut.append("\nEnvironment:  ");
	//			transcriptOut.append(environment.toString64());
				transcriptOut.append("\n\n");
			}
			return toReturn;
		}
		return verified;
	}
	
	protected abstract boolean verifyResponse(CryptoData input, CryptoData a, CryptoData z, BigInteger challenge, CryptoData environment);
	@SuppressWarnings("rawtypes")
	public static ZKPVerifier generateVerifier(String string) throws InvalidStringFormatException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, SecurityException {
		String str = string;
		int place = string.indexOf('(');
		ZKPVerifier toReturn = null;
		if(place != -1) //If it is compound, it has a paren.
		{
			if(string.charAt(string.length()-1) != ')')
				throw new InvalidStringFormatException();
			str = string.substring(0, place);
			int protocol = -1;
			for(int i = 0; i < compoundProtocols.size(); i++)
			{
				if(compoundProtocols.get(i).name.equals(str))
				{
					protocol = i;
					break;
				}
			}
			
			if(protocol == -1)
				throw new InvalidStringFormatException();	//Maybe I should make a better exception name for this one.
			
			String args = string.substring(place+1, string.length()-1);
			int inParens = 0;
			int start = 0;
			int verifiersIndex = 0;  
			int verifierNum = 1;
			for(int i = 0; i < args.length(); i++)
			{
				char p = args.charAt(i);
				if(p == '(') inParens++;
				if(p == ')') inParens--;
				if(p == ',' && inParens == 0)
				{
					if(start == i) throw new InvalidStringFormatException();
					verifierNum++;
					start = i + 1;
				}
			}
			if(inParens != 0) throw new InvalidStringFormatException();
			start = 0;
			ZKPVerifier[] verifiers = new ZKPVerifier[verifierNum];
			for(int i = 0; i < args.length(); i++)
			{
				char p = args.charAt(i);
				if(p == '(') inParens++;
				if(p == ')') inParens--;
				if(inParens < 0) throw new InvalidStringFormatException();
				if((p == ',') && inParens == 0)
				{
					verifiers[verifiersIndex] = generateVerifier(args.substring(start, i));
					verifiersIndex++;
					start = i + 1;
				}
			}
			verifiers[verifiersIndex] = generateVerifier(args.substring(start));
			verifiersIndex++;
			toReturn = (ZKPVerifier) compoundProtocols.get(protocol).protocol.getConstructors()[0].newInstance(new Object[] {verifiers});
		} 
		else { // It is not a compound statement or it not presented correctly.
			Class toMake = null;
			for(int i = 0; i < protocols.size(); i++)
			{
				if(string.equals(protocols.get(i).name))
				{
					toMake = protocols.get(i).protocol;
					break;
				}
			}
			toReturn = (ZKPVerifier) toMake.newInstance();
		}
		return toReturn;
	}
}

