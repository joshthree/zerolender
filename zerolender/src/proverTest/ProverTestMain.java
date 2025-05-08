package proverTest;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.DLSchnorrProver;
import zero_knowledge_proofs.ECPedersenCommitment;
import zero_knowledge_proofs.ECSchnorrProver;
import zero_knowledge_proofs.ECSchnorrVerifier;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKPVerifier;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class ProverTestMain {
	public static void main(String[] args) throws IOException, ClassNotFoundException, MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException
	{

		ServerSocket host = new ServerSocket(Integer.parseInt(args[0]));
		System.out.println("Waiting for Verifier...");
		Socket s = host.accept();
		ECPoint g = ECNamedCurveTable.getParameterSpec("secp256k1").getG();
		ECCurve curve = g.getCurve();
		BigInteger x = new BigInteger(args[1]);
		ECPoint y = g.multiply(x); 
		BigInteger r = new BigInteger(args[2]);
		CryptoData input = new CryptoDataArray(new CryptoData[] {new BigIntData(x), new ECPointData(y), new BigIntData(r)});
		
		CryptoData environment = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, g)});
		ZKPProtocol prover = new ECSchnorrProver();
		ObjectInputStream in = new ObjectInputStream(s.getInputStream());
		ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
		System.out.println("Starting Prover");
		try {
			System.out.println(prover.prove(input, environment, in, out));
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Ending Prover");
		out.close();
		in.close();
		s.close();
		host.close();
	}

	private static void usage() {
		System.err.println("Error:  Invalid Argumments");
		System.err.println("[Port (12345)] [secret (x)] [initial comm secret (r)]");
	}
}
