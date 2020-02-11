package dns;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class DnsAnswer {
	private String NAME, TMPNAME, RDATA;
	private String TYPE, CLASS;
	private int TTL, RDLENGTH, PREFERENCE;
	private byte AA;
	private String output;

	public DnsAnswer(byte aa) {
		this.AA = aa;
	}

	public int parseAnswer(int startIndex, byte[] dnsResponse) {
		int index = getServerNameFromIndex(startIndex, dnsResponse);
		this.NAME = this.TMPNAME;
		// get type:
		if (dnsResponse[index] == 0) {
			switch (dnsResponse[index + 1]) {
			case 1:
				this.TYPE = "A";
				break;
			case 2:
				this.TYPE = "NS";
				break;
			case 5:
				this.TYPE = "CNAME";
				break;
			case 15:
				this.TYPE = "MX";
				break;
			default:
				System.out.println("ERROR\tUnrecognized response type");
			}
		} else {
			System.out.println("ERROR\tUnrecognized response type");
		}

		// get class:
		index += 2;
		if (dnsResponse[index] != 0 || dnsResponse[index + 1] != 1) {
			throw new RuntimeException(("ERROR\tThe class field in the response is not 1"));
		}

		// get ttl:
		index += 2;
		this.TTL = dnsResponse[index] << 24 | dnsResponse[index + 1] << 16 | dnsResponse[index + 2] << 8
				| dnsResponse[index + 3];

		// get rdlength:
		index += 4;
		this.RDLENGTH = dnsResponse[index] << 8 | dnsResponse[index + 1];

		// get rdata:
		index += 2;
		switch (this.TYPE) {
		case "A":
			this.RDATA = getRDataA(index, dnsResponse);
			index += 4;
			setOutput("IP");
			break;
		case "NS":
			index = getServerNameFromIndex(index, dnsResponse);
			this.RDATA = this.TMPNAME;
			setOutput("NS");
			break;
		case "MX":
			index = setRDataMX(index, dnsResponse);
			setOutput("MX");
			break;
		case "CNAME":
			index = getServerNameFromIndex(index, dnsResponse);
			this.RDATA = this.TMPNAME;
			setOutput("CNAME");
			break;
		}
		return index;
	}

	private String getRDataA(int index, byte[] answers) {
		String rdata = "";
		byte[] serverIp = new byte[4];
		for (int i = 0; i < serverIp.length; i++) {
			serverIp[i] = answers[index + i];
		}
		try {
			InetAddress ad = InetAddress.getByAddress(serverIp);
			rdata = ad.toString().substring(1);
		} catch (UnknownHostException e) {
			System.out.println("ERROR\tThe IP address cannot be resolved in the response");
		}
		return rdata;
	}

	private int setRDataMX(int index, byte[] answer) {
		int preference = answer[index] << 8 | answer[index + 1];
		this.PREFERENCE = preference;
		index = getServerNameFromIndex(index, answer);
		this.RDATA = this.TMPNAME;
		return index;
	}

	public String getComponentFromIndex(int wordlen, int index, byte[] answer) {
		String component = "";
		for (int i = 0; i < wordlen; i++) {
			component += (char) answer[index + i];
		}
		return component;
	}

	public int getServerNameFromIndex(int index, byte[] answer) {
		String name = "";
		int wordlen = answer[index];
		while (wordlen != 0) {
			if (!((wordlen & 0xC0) == (int) 0xC0)) {
				name += getComponentFromIndex(wordlen, index + 1, answer);
				index += wordlen + 1;
				wordlen = answer[index];
			} else {
				int pointer = (answer[index] & 0x3F) << 8 | answer[index+1];
				getServerNameFromIndex(pointer, answer);
				name += this.TMPNAME;
				index += 2;
				wordlen = 0;
			}
			if (wordlen != 0) {
				name += ".";
			}
		}
		this.TMPNAME = name;
		return index;
	}

	public String getNAME() {
		return this.NAME;
	}

	public byte getAA() {
		return this.AA;
	}

	private void setOutput(String type) {
		String auth = this.AA == 1 ? "auth" : "nonauth";
		String outputStr = type + "\t" + this.RDATA + "\t";
		if (type.equals("MX")) {
			outputStr += this.PREFERENCE + "\t";
		}
		outputStr += this.TTL + "\t" + auth;
		this.output = outputStr;
	}

	public String getOutput() {
		return this.output;
	}
}
