package proverTest;

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.InvalidStringFormatException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.DLSchnorrProver;
import zero_knowledge_proofs.ECEqualDiscreteLogsProver;
import zero_knowledge_proofs.ECEqualDiscreteLogsVerifier;
import zero_knowledge_proofs.ECProofOfPrechosenExponentProver;
import zero_knowledge_proofs.ECSchnorrProver;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZeroKnowledgeAndProver;
import zero_knowledge_proofs.ZeroKnowledgeOrProver;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class GeneralProverTestMain {
	public static void main(String[] args) throws IOException, ClassNotFoundException, MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, SecurityException, InvalidStringFormatException
	{
		ZKPProtocol.registerProtocol("DLSchnorr", DLSchnorrProver.class, false);
		ZKPProtocol.registerProtocol("ECSchnorr", ECSchnorrProver.class, false);
		ZKPProtocol.registerProtocol("ECEqualLog", ECEqualDiscreteLogsProver.class, false);
		ZKPProtocol.registerProtocol("AND", ZeroKnowledgeAndProver.class, true);
		ZKPProtocol.registerProtocol("OR", ZeroKnowledgeOrProver.class, true);
		ZKPProtocol prover = ZKPProtocol.generateProver("OR(ECEqualLog,ECEqualLog)");
		
		
		Scanner envFile = new Scanner(new File(args[2]));
		ECPoint g = ECNamedCurveTable.getParameterSpec(envFile.next()).getG();
		ECPoint h = g.multiply(new BigInteger(envFile.next()));
		ECCurve c = g.getCurve();
		BigInteger order = g.getCurve().getOrder();
		int bitLength = order.bitLength();
		
		CryptoData miniEnv = new CryptoDataArray(new CryptoData[] {new ECCurveData(c, g), new ECPointData(h)});
		CryptoData environment = new CryptoDataArray(new CryptoData[] {miniEnv, miniEnv});
		
		BigInteger x = new BigInteger(args[3]);
		BigInteger r = new BigInteger(args[4]);
		CryptoData innerInput = new CryptoDataArray(new CryptoData[] {new ECPointData(g.multiply(x)), new ECPointData(h.multiply(x)), new BigIntData(r), new BigIntData(x)});
		CryptoData input = new CryptoDataArray(new CryptoData[] {innerInput, innerInput, new CryptoDataArray(new BigInteger[] {BigInteger.ZERO, new BigInteger(args[5])})});
		
		ServerSocket host = new ServerSocket(Integer.parseInt(args[0]));
		System.out.println("Waiting for Verifier...");
		Socket s = host.accept();
		ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
		ObjectInputStream in = new ObjectInputStream(s.getInputStream());
		System.out.println("Starting Prover");
		try {
			System.out.println(prover.prove(input, environment, in, out));
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("Ending Prover");
		out.close();
		in.close();
		s.close();
		host.close();
	}
}
