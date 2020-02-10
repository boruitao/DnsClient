package dns;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;

public class DnsQuestion {
	private short QTYPE;
	private byte[] question;

	public DnsQuestion(String qname, String qtype) {
		String[] components = qname.split("\\.");
		int len = 0;
		for (int i = 0; i < components.length; i++) {
			len += components[i].length() + 1;
		}
		len++;
		ByteBuffer dnsQuestion = ByteBuffer.allocate(len + 4);

		for (int i = 0; i < components.length; i++) {
			dnsQuestion.put((byte) components[i].length());
			try {
				dnsQuestion.put(components[i].getBytes("UTF-8"));
			} catch (UnsupportedEncodingException e) {
				System.out.println("ERROR\tThe specified char cannot be encoded");
			}
		}

		switch (qtype) {
		case "A":
			this.QTYPE = 0x0001;
			break;
		case "NS":
			this.QTYPE = 0x0002;
			break;
		case "MX":
			this.QTYPE = 0x000f;
			break;
		}

		dnsQuestion.put((byte) 0x00);
		dnsQuestion.putShort(this.QTYPE);
		dnsQuestion.put((byte) 0x00);
		dnsQuestion.put((byte) 0x0001);

		this.question = dnsQuestion.array();
	}

	public byte[] getQuestion() {
		return this.question;
	}
}
