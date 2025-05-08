package zerolenderProtocol;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.channels.ScatteringByteChannel;
import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.Queue;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.ECSchnorrProver;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.ZeroKnowledgeAndProver;
import zero_knowledge_proofs.ZeroKnowledgeOrProver;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class ProverProtocolPart3 {
	public static void main(String[] args) throws FileNotFoundException, IOException, ClassNotFoundException, MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		//basename 
		String baseName = args[0];

		ECSchnorrProver schnorr = new ECSchnorrProver();
		SecureRandom rand = new SecureRandom();
		ECPoint g = ECNamedCurveTable.getParameterSpec("secp256k1").getG();
		ECCurve c = g.getCurve();
		BigInteger order = g.getCurve().getOrder();

		System.out.println(baseName);
		System.out.println(baseName+ "_pub");
		System.out.println(baseName+ "_priv");

		ObjectInputStream mainIn = new ObjectInputStream(new FileInputStream(new File(baseName)));
		ObjectInputStream mainInPub = new ObjectInputStream(new FileInputStream(new File(baseName + "_pub")));
		ObjectInputStream mainInPriv = new ObjectInputStream(new FileInputStream(new File(baseName + "_priv")));

		ECPointData hPacked = (ECPointData) mainInPub.readObject(); 
		ECPoint h = hPacked.getECPointData(c);
		//		int numInvestors = mainInPub.readInt();

		int numTransaction = mainIn.readInt();

		BigInteger[] amounts = new BigInteger[numTransaction];

		CryptoData[] clientCommitmentsPacked = ((CryptoDataArray) mainInPub.readObject()).getCryptoDataArray();
		CryptoData[] amountCommitmentsPacked = ((CryptoDataArray) mainInPub.readObject()).getCryptoDataArray();

		ECPoint[] clientCommitments = new ECPoint[clientCommitmentsPacked.length];
		ECPoint[] amountCommitments = new ECPoint[amountCommitmentsPacked.length];

		for(int i = 0; i < amountCommitmentsPacked.length; i++) {
			clientCommitments[i] = clientCommitmentsPacked[i].getECPointData(c);
			amountCommitments[i] = amountCommitmentsPacked[i].getECPointData(c);
		}

		BigInteger[] clientAddresses = (BigInteger[]) mainInPriv.readObject();
		BigInteger[] clientKeys = (BigInteger[]) mainInPriv.readObject();

		int numOwnedTransaction = mainInPriv.readInt();
		int[] investorAmounts = (int[]) mainInPriv.readObject();
		BigInteger[] amountPrivateKeys = (BigInteger[]) mainInPriv.readObject();


		Queue<InnerThing> ownedTransactions = new LinkedList<InnerThing>();

		int[] accountNumber = new int[numOwnedTransaction];
		BigInteger[] accountPrivateKey = new BigInteger[numOwnedTransaction];

		ECPointData[] accountPublicKeys = new ECPointData[numTransaction];
		BigInteger[] addresses = new BigInteger[numTransaction];

		for(int i = 0; i < numOwnedTransaction; i++) {
			InnerThing account = new InnerThing();
			account.account = mainInPriv.readInt();
			account.owner = mainInPriv.readInt();
			account.accountPrivateKey = (BigInteger) mainInPriv.readObject();
			ownedTransactions.offer(account);
			//			accountNumber[i] = mainInPriv.readInt();
			//			owner[i] = mainInPriv.readInt();
			//			accountKey[i] = (BigInteger) mainInPriv.readObject();
		}
		for(int i = 0; i < numTransaction; i++) {
			addresses[i] = (BigInteger) mainIn.readObject();
			accountPublicKeys[i] = (ECPointData) mainIn.readObject();
			amounts[i] = BigInteger.valueOf(mainIn.readInt());
		}

		ZKPProtocol prover = createProof();

		InnerThing current = ownedTransactions.poll();
		CryptoData[][][] data = new CryptoData[4][3][];
		CryptoData[] challenges = new CryptoData[2];
		for(int i = 0; i < 4; i++) {
			data[i][0] = new CryptoData[1];
			data[i][1] = new CryptoData[1];
			data[i][2] = new CryptoData[2];
		}
		ECPoint[] commitmentSums = new ECPoint[clientKeys.length];
		BigInteger[] commitmentSumsKeys = new BigInteger[clientKeys.length];
		BigInteger[] commitmentAmounts = new BigInteger[clientKeys.length];
		for(int i = 0; i < clientKeys.length; i++) {
			commitmentSums[i] = c.getInfinity();
			commitmentSumsKeys[i] = BigInteger.ZERO;
			commitmentAmounts[i] = BigInteger.ZERO;
		}
		CryptoData gEnv = new CryptoDataArray(new CryptoData[] {new ECCurveData(c, g)});
		CryptoData hEnv = new CryptoDataArray(new CryptoData[] {new ECCurveData(c, h)});

		CryptoData[][][] results = new CryptoData[addresses.length][clientCommitments.length][];

		CryptoData zero = new BigIntData(BigInteger.ZERO);                                                                                                                                   

		CryptoData environment = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(new CryptoData[] {gEnv, hEnv, hEnv}), hEnv});
		for(int i = 0; i < numTransaction; i++) {
			ECPoint gAddress = g.multiply(addresses[i]);

			data[0][0][0] = accountPublicKeys[i];
			for(int j = 0; j < clientCommitments.length; j++) {
				data[1][0][0] = new ECPointData(clientCommitments[j].subtract(gAddress));

				if(current != null && current.account == i && current.owner == j) {
					BigInteger key = ZKToolkit.random(order, rand);
					ECPoint keySide = h.multiply(key);
					ECPoint comm = g.multiply(amounts[i]).add(keySide);
					data[2][0][0] = new ECPointData(keySide);
					data[3][0][0] = new ECPointData(comm);

					data[0][2][0] = new BigIntData(ZKToolkit.random(order, rand));
					data[0][2][1] = new BigIntData(current.accountPrivateKey);

					data[1][2][0] = new BigIntData(ZKToolkit.random(order, rand));
					data[1][2][1] = new BigIntData(clientKeys[j]);

					data[2][2][0] = new BigIntData(ZKToolkit.random(order, rand));
					data[2][2][1] = new BigIntData(key);

					data[3][1][0] = new BigIntData(ZKToolkit.random(order, rand));

					challenges[0] = zero;
					challenges[1] = new BigIntData(new BigInteger(255, rand));

					CryptoData[] innerPub = new CryptoData[] {new CryptoDataArray(new CryptoData[] {data[0][0][0]}), new CryptoDataArray(new CryptoData[] {data[1][0][0]}), new CryptoDataArray(new CryptoData[] {data[2][0][0]})};
					CryptoData publicInputs = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(innerPub), new CryptoDataArray(new CryptoData[] {data[3][0][0]})});

					CryptoData[] innerPriv = new CryptoData[] {new CryptoDataArray(new CryptoData[] {data[0][2][0],data[0][2][1]}), new CryptoDataArray(new CryptoData[] {data[1][2][0],data[1][2][1]}), new CryptoDataArray(new CryptoData[] {data[2][2][0],data[2][2][1]})};
					CryptoData privateInputs = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(innerPriv), new CryptoDataArray(new CryptoData[] {data[3][1][0]}), new CryptoDataArray(challenges)});

					results[i][j] = prover.proveFiatShamir(publicInputs, privateInputs, environment);

					//					if(!prover.verifyFiatShamir(publicInputs, results[i][j][0], results[i][j][1], environment)) {
					//						System.out.println("PANIC 1");
					//						System.out.println(data[1][0][0].getECPointData(c).equals(h.multiply(clientKeys[j])));
					//						return;
					//					}

					commitmentSums[j] = commitmentSums[j].add(comm);
					commitmentSumsKeys[j] = commitmentSumsKeys[j].add(key);
					commitmentAmounts[j] = commitmentAmounts[j].add(amounts[i]);
					current = ownedTransactions.poll();
				} else {

					BigInteger key = ZKToolkit.random(order, rand);
					ECPoint keySide = h.multiply(key);
					ECPoint comm = keySide;
					data[2][0][0] = new ECPointData(keySide);
					data[3][0][0] = new ECPointData(comm);

					data[0][1][0] = new BigIntData(ZKToolkit.random(order, rand));
					data[1][1][0] = new BigIntData(ZKToolkit.random(order, rand));
					data[2][1][0] = new BigIntData(ZKToolkit.random(order, rand));

					data[3][2][0] = new BigIntData(ZKToolkit.random(order, rand));
					data[3][2][1] = new BigIntData(key);

					commitmentSums[j] = commitmentSums[j].add(comm);
					commitmentSumsKeys[j] = commitmentSumsKeys[j].add(key);

					challenges[0] = new BigIntData(new BigInteger(255, rand));
					challenges[1] = zero;

					CryptoData[] innerPub = new CryptoData[] {new CryptoDataArray(new CryptoData[] {data[0][0][0]}), new CryptoDataArray(new CryptoData[] {data[1][0][0]}), new CryptoDataArray(new CryptoData[] {data[2][0][0]})};
					CryptoData publicInputs = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(innerPub), new CryptoDataArray(new CryptoData[] {data[3][0][0]})});

					CryptoData[] innerPriv = new CryptoData[] {new CryptoDataArray(new CryptoData[] {data[0][1][0]}), new CryptoDataArray(new CryptoData[] {data[1][1][0]}), new CryptoDataArray(new CryptoData[] {data[2][1][0]})};
					CryptoData privateInputs = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(innerPriv), new CryptoDataArray(new CryptoData[] {data[3][2][0],data[3][2][1]}), new CryptoDataArray(challenges)});

					results[i][j] = prover.proveFiatShamir(publicInputs, privateInputs, environment);

					commitmentSums[j] = commitmentSums[j].add(comm);
					commitmentSumsKeys[j] = commitmentSumsKeys[j].add(key);
					//					if(!prover.verifyFiatShamir(publicInputs, results[i][j][0], results[i][j][1], environment)) {
					//						System.out.println("PANIC 2");
					//						return;
					//					}
				}
			}
		}

		CryptoData[][] finalResults = new CryptoData[clientCommitments.length][];
		for(int i = 0; i < finalResults.length; i++) {
			CryptoData pub = new CryptoDataArray(new ECPoint[] {amountCommitments[i].subtract(commitmentSums[i])});
			CryptoData secrets = new CryptoDataArray(new BigInteger[]  {ZKToolkit.random(order, rand),amountPrivateKeys[i].subtract(commitmentSumsKeys[i])});
			finalResults[i] = schnorr.proveFiatShamir(pub, secrets, hEnv);
			if(!schnorr.verifyFiatShamir(pub, finalResults[i][0], finalResults[i][1], hEnv)) {
				
				System.out.println("Ugghhhh");
				if(!BigInteger.valueOf(investorAmounts[i]).equals(commitmentAmounts[i])) System.out.println("NOOOOOO");
				if(!g.multiply(commitmentAmounts[i]).add(h.multiply(commitmentSumsKeys[i])).equals(commitmentSums[i])) System.out.println("Is this it?");
				if(!g.multiply(BigInteger.valueOf(investorAmounts[i])).add(h.multiply(amountPrivateKeys[i])).equals(amountCommitments[i])) System.out.println("Is this it 2.0?");
				
				if(!h.multiply(amountPrivateKeys[i].subtract(commitmentSumsKeys[i])).equals(amountCommitments[i].subtract(commitmentSums[i]))) System.out.println("oh...");
			}
		}
		
		ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(new File(baseName + "_results")));
		
	}

	public static ZKPProtocol createProof() {
		ECSchnorrProver schnorr = new ECSchnorrProver();

		//Either I know the key AND the commitment hides the address AND the commitment hides the amount OR the commitment hides 0

		ZKPProtocol[] array = new ZKPProtocol[] {schnorr, schnorr, schnorr};

		ZeroKnowledgeAndProver blah = new ZeroKnowledgeAndProver(array);

		ZeroKnowledgeOrProver toReturn = new ZeroKnowledgeOrProver(new ZKPProtocol[] {blah, schnorr});

		return toReturn;
	}

}
class InnerThing{
	public int owner;
	public int account;
	public BigInteger accountPrivateKey;
}
