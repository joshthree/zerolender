package zero_knowledge_proofs;

public class ProverProtocolPair
{
	public final String name;
	@SuppressWarnings("rawtypes")
	public final Class protocol;
	
	@SuppressWarnings({ "rawtypes" }) ProverProtocolPair(String name, Class protocol) throws ClassCastException
	{
		this.name = name;
		if(ZKPProtocol.class.isAssignableFrom(protocol))
			this.protocol = protocol;
		else 
			throw new ClassCastException();
	}
}