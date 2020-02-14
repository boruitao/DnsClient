package dns;

public class DnsResponse {
	private byte[] dnsResponse;
	private DnsHeader header;
	private DnsAnswer[] answers;
	private DnsAnswer[] authorities;
	private DnsAnswer[] additionals;
	private int startIndex;

	/**
	 * This class is used to parse the answer, authority, and the additional
	 * sections. It creates each individual answer based on the response data.
	 * 
	 * @param dnsResponse
	 * @param receivedHeader
	 * @param startIndex
	 */
	public DnsResponse(byte[] dnsResponse, DnsHeader receivedHeader, int startIndex) {
		this.dnsResponse = dnsResponse;
		this.header = receivedHeader;
		this.startIndex = startIndex;
		parseResponse();
	}

	public void parseResponse() {
		int ancount = header.getANCOUNT();
		int nscount = header.getNSCOUNT();
		int arcount = header.getARCOUNT();
		int index = startIndex;
		answers = new DnsAnswer[ancount];
		authorities = new DnsAnswer[nscount];
		additionals = new DnsAnswer[arcount];

		for (int i = 0; i < answers.length; i++) {
			answers[i] = new DnsAnswer(header.getAA());
			index = answers[i].parseAnswer(index, dnsResponse);
		}

		for (int i = 0; i < authorities.length; i++) {
			authorities[i] = new DnsAnswer(header.getAA());
			index = authorities[i].parseAnswer(index, dnsResponse);
		}

		for (int i = 0; i < additionals.length; i++) {
			additionals[i] = new DnsAnswer(header.getAA());
			index = additionals[i].parseAnswer(index, dnsResponse);
		}
	}

	public void printResponseOutput() {
		System.out.println("");
		int ancount = header.getANCOUNT();
		int arcount = header.getARCOUNT();
		boolean isCaseThree = header.validateRCode();
		if (ancount <= 0 || isCaseThree) {
			System.out.println("NOTFOUND");
		} else {
			System.out.println("***Answer Section (" + ancount + " records)***");
			for (DnsAnswer an : this.answers) {
				if (!an.getTYPE().equals("OTHER"))
					System.out.println(an.getOutput());
			}
			System.out.println("");
			if (arcount > 0) {
				System.out.println("***Additional Section (" + arcount + " records)***");
				for (DnsAnswer an : this.additionals) {
					if (!an.getTYPE().equals("OTHER"))
						System.out.println(an.getOutput());
				}
			}
		}

	}
}
