package dns;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public class DnsAnswer {
	private String NAME, TMPNAME, RDATA;
	private String TYPE;
	private short CLASS;
	private int TTL, RDLENGTH, PREFERENCE;
	private byte AA;
	private String output;

	public DnsAnswer(byte aa) {
		this.AA = aa;
	}

	/**
	 * Parse the answers, authorities, and the additionals based on the response
	 * data, which have similar format. It also checks if the CLASS is 0x0001. If
	 * not, it throws a RunTimeException.
	 * 
	 * @param startIndex  : the starting index of the answer section.
	 * @param dnsResponse : the response data.
	 */
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
			System.out.println("\nERROR \tUnrecognized response type");
		}

		// move to the next two bytes to get class:
		index += 2;
		this.CLASS = ByteBuffer.wrap(getByteArrFromIndex(index, 2, dnsResponse)).getShort();
		if (this.CLASS != 0x0001) {
			throw new RuntimeException(("\nERROR \tThe class field in the response is not 1"));
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

	private String getRDataA(int index, byte[] dnsResponse) {
		String rdata = new String();
		byte[] serverIp = new byte[4];
		for (int i = 0; i < serverIp.length; i++) {
			serverIp[i] = dnsResponse[index + i];
		}
		try {
			InetAddress ad = InetAddress.getByAddress(serverIp);
			rdata = ad.toString().substring(1);
		} catch (UnknownHostException e) {
			System.out.println("\nERROR \tThe IP address cannot be resolved in the response");
		}
		return rdata;
	}

	private int setRDataMX(int index, byte[] dnsResponse) {
		int preference = ByteBuffer.wrap(getByteArrFromIndex(index, 2, dnsResponse)).getShort();
		this.PREFERENCE = preference;
		index = getServerNameFromIndex(index + 2, dnsResponse);
		this.RDATA = this.TMPNAME;
		return index;
	}

	public String getComponentFromIndex(int len, int index, byte[] dnsResponse) {
		StringBuilder component = new StringBuilder();
		for (int i = 0; i < len; i++) {
			component.append((char) dnsResponse[index + i]);
		}
		return component.toString();
	}

	/**
	 * This recursive method handles DNS packet compression. The domain name in the
	 * message can either be a sequence of labels ending with 0, or a pointer, or a
	 * sequence of labels ending with a pointer. This method handles all the cases
	 * by doing recursive calls if a pointer is detected.
	 * 
	 * Base case: if the data is 0 which means the length of the word is 0, return
	 * an empty string.
	 * 
	 * Recursive step: if the data is not 0 and it is not a pointer, we get each
	 * component of the domain name between the dot and return the whole string. If
	 * the a pointer is found, we calculate the offset and obtain the word
	 * corresponding to that location. This is done by calling this method
	 * recursively using the offset.
	 * 
	 * @param index
	 * @param dnsResponse
	 * @return
	 */
	public int getServerNameFromIndex(int index, byte[] dnsResponse) {
		int currByte = dnsResponse[index];
		if (currByte == 0) {
			this.TMPNAME = "";
			return index;
		}
		StringBuilder name = new StringBuilder();
		do {
			if (!((currByte & 0xC0) == (int) 0xC0)) {
				name.append(getComponentFromIndex(currByte, index + 1, dnsResponse));
				index += currByte + 1;
				currByte = dnsResponse[index];
				if (currByte == 0)
					index++;
			} else {
				byte[] pointerArr = new byte[2];
				pointerArr[0] = (byte) (dnsResponse[index] & 0x3F);
				pointerArr[1] = dnsResponse[index + 1];
				int pointer = ByteBuffer.wrap(pointerArr).getShort();
				getServerNameFromIndex(pointer, dnsResponse);
				name.append(this.TMPNAME);
				index += 2;
				currByte = 0;
			}
			if (currByte != 0) {
				name.append(".");
			}
		} while (currByte != 0);
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
