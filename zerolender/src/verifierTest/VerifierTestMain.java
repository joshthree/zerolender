package verifierTest;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import commitment.ECPedersenCommitment;
import zero_knowledge_proofs.ZKPDataArray;
import zero_knowledge_proofs.DLSchnorrVerifier;
import zero_knowledge_proofs.ECCurveData;
import zero_knowledge_proofs.ECPointData;
import zero_knowledge_proofs.ECSchnorrVerifier;
import zero_knowledge_proofs.ZKPData;
import zero_knowledge_proofs.ZKPVerifierInterface;

public class VerifierTestMain {
	public static void main(String[] args) throws IOException, ClassNotFoundException
	{
		if(args.length < 4) 
		{
			usage();
			System.exit(1);
		}
		SocketAddress dest = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
		Socket s = new Socket();
		s.connect(dest);
		ECPoint g = ECNamedCurveTable.getParameterSpec("secp256k1").getG();
		ECCurve curve = g.getCurve();
		BigInteger x = new BigInteger(args[2]);
		ECPoint y = g.multiply(x); 
		ZKPData input = new ZKPDataArray(new ZKPData[] {new ECPointData(y)});
		BigInteger c = new BigInteger(args[3]);

		ZKPData environment = new ZKPDataArray(new ZKPData[] {new ECCurveData(curve, g)});

		ZKPVerifierInterface prover = new ECSchnorrVerifier();
		System.out.println("Starting Verifier");
		ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
		ObjectInputStream in = new ObjectInputStream(s.getInputStream());
		ZKPData commEnv = new ZKPDataArray(new ZKPData[] {new ECCurveData(curve, g), new ECPointData(y)});
		ECPedersenCommitment comm1 = new ECPedersenCommitment(x, new BigInteger[] {c}, commEnv);
		ECPedersenCommitment comm2 = new ECPedersenCommitment(x, new BigInteger[] {c}, commEnv);
		if(comm1.verifyCommitment(x, new BigInteger[] {c}, commEnv)) System.out.println("yay");
		else System.out.println("nooooo!");
		try {
			System.out.println(prover.verify(input, c, environment, in, out));
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


	private static void usage() {
		System.err.println("Error:  Invalid Argumments");
		System.err.println("[Prover IP (e.g. 127.0.0.1)] [Port (e.g. 12345)] [secret (x)] [challenge]");
	}
}
