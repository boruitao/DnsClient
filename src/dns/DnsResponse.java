package dns;

public class DnsResponse {
	private byte[] dnsResponse;
	private DnsHeader header;
	private DnsQuestion question;
	private DnsAnswer[] answers;
	private DnsAnswer[] authorities;
	private DnsAnswer[] additionals;
	private int startIndex;
	private static final int MAX_DNS_PACKET_SIZE = 512;

	public DnsResponse(byte[] dnsResponse, DnsHeader receivedHeader, DnsQuestion receivedQuestion, int startIndex) {
		this.dnsResponse = dnsResponse;
		this.header = receivedHeader;
		this.question = receivedQuestion;
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
			answers[i] = new DnsAnswer(header.getAA());
			index = additionals[i].parseAnswer(index, dnsResponse);
		}
	}

	public void printResponseOutput() {
		System.out.println("");
		int ancount = header.getANCOUNT();
		int arcount = header.getARCOUNT();
		if (ancount <= 0) {
			System.out.println("NOTFOUND");
		} else {
			System.out.println("***Answer Section (" + ancount + " records)***");
			for (DnsAnswer an : this.answers) {
				System.out.println(an.getOutput());
			}
			System.out.println("");
			if (arcount > 0) {
				System.out.println("***Additional Section (" + arcount + " records)***");
				for (DnsAnswer an : this.additionals) {
					System.out.println(an.getOutput());
				}
			}
		}

	}
}
