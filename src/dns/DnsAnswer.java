package dns;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

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
				this.TYPE = "OTHER";
				break;
			}
		} else {
			System.out.println("ERROR\tUnrecognized response type");
		}

		// move to the next two bytes to get class:
		index += 2;
		if (dnsResponse[index] != 0 || dnsResponse[index + 1] != 1) {
			throw new RuntimeException(("ERROR\tThe class field in the response is not 1"));
		}

		// move to the next two bytes to get ttl:
		index += 2;
		this.TTL = ByteBuffer.wrap(getByteArrFromIndex(index, 4, dnsResponse)).getInt();

		// move to the next four bytes to get rdlength:
		index += 4;
		this.RDLENGTH = ByteBuffer.wrap(getByteArrFromIndex(index, 2, dnsResponse)).getShort();
		// move to the next two bytes get rdata:
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
		String rdata = new String();
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
		int preference = ByteBuffer.wrap(getByteArrFromIndex(index, 2, answer)).getShort();
		this.PREFERENCE = preference;
		index = getServerNameFromIndex(index + 2, answer);
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
		StringBuilder name = new StringBuilder();
		int currByte = answer[index];
		while (currByte != 0) {
			if (!((currByte & 0xC0) == (int) 0xC0)) {
				name.append(getComponentFromIndex(currByte, index + 1, answer));
				index += currByte + 1;
				currByte = answer[index];
			} else {
				byte[] pointerArr = new byte[2];
				pointerArr[0] = (byte) (answer[index] & 0x3F);
				pointerArr[1] = answer[index + 1];
				int pointer = ByteBuffer.wrap(pointerArr).getShort();
				getServerNameFromIndex(pointer, answer);
				name.append(this.TMPNAME);
				index += 2;
				currByte = 0;
			}
			if (currByte != 0) {
				name.append(".");
			}
		}
		this.TMPNAME = name.toString();
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

	public byte[] getByteArrFromIndex(int index, int len, byte[] response) {
		byte[] arr = new byte[len];
		for (int i = 0; i < arr.length; i++) {
			arr[i] = response[index + i];
		}
		return arr;
	}
}
