package verifierTest;

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.Scanner;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.InvalidStringFormatException;
import zero_knowledge_proofs.DLSchnorrVerifier;
import zero_knowledge_proofs.ECEqualDiscreteLogsVerifier;
import zero_knowledge_proofs.DLSchnorrVerifier;
import zero_knowledge_proofs.ECProofOfPrechosenExponentVerifier;
import zero_knowledge_proofs.ECSchnorrVerifier;
import zero_knowledge_proofs.ZKPVerifier;
import zero_knowledge_proofs.ZeroKnowledgeAndVerifier;
import zero_knowledge_proofs.ZeroKnowledgeAndVerifier;
import zero_knowledge_proofs.ZeroKnowledgeOrVerifier;
import zero_knowledge_proofs.ZeroKnowledgeOrVerifier;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class GeneralVerifierTestMain {
	public static void main(String[] args) throws IOException, ClassNotFoundException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, SecurityException, InvalidStringFormatException
	{
		ZKPVerifier.registerProtocol("DLSchnorr", DLSchnorrVerifier.class, false);
		ZKPVerifier.registerProtocol("ECSchnorr", ECSchnorrVerifier.class, false);
		ZKPVerifier.registerProtocol("ECEqualLog", ECEqualDiscreteLogsVerifier.class, false);
		ZKPVerifier.registerProtocol("AND", ZeroKnowledgeAndVerifier.class, true);
		ZKPVerifier.registerProtocol("OR", ZeroKnowledgeOrVerifier.class, true);
		ZKPVerifier verifier = ZKPVerifier.generateVerifier("OR(ECEqualLog,ECEqualLog)");
		System.out.println(verifier);
		
		Scanner envFile = new Scanner(new File(args[3]));
		ECPoint g = ECNamedCurveTable.getParameterSpec(envFile.next()).getG();
		ECPoint h = g.multiply(new BigInteger(envFile.next()));
		ECCurve c = g.getCurve();
		BigInteger order = g.getCurve().getOrder();
		int bitLength = order.bitLength();
		
		CryptoData miniEnv = new CryptoDataArray(new CryptoData[] {new ECCurveData(c, g), new ECPointData(h)});
		CryptoData environment = new CryptoDataArray(new CryptoData[] {miniEnv, miniEnv});
		
		BigInteger x = new BigInteger(args[4]);
		BigInteger r = new BigInteger(args[5]);
		CryptoData innerInput = new CryptoDataArray(new CryptoData[] {new ECPointData(g.multiply(x)), new ECPointData(h.multiply(x))});
		CryptoData input = new CryptoDataArray(new CryptoData[] {innerInput, innerInput});
		
		SocketAddress dest = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
		Socket s = new Socket();
		s.connect(dest);
		
		BigInteger challenge = new BigInteger(args[6]);
		
		System.out.println("Starting Verifier");
		ObjectInputStream in = new ObjectInputStream(s.getInputStream());
		ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
		
		try {
			System.out.println(verifier.verify(input, challenge, environment, in, out, null));
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("Ending Verifier");
		in.close();
		out.close();
		s.close();
	}

}
