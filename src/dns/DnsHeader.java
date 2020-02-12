package dns;

public class DnsHeader {
	private short ID;
	private byte QR, OPCODE, AA, TC, RD, RA, Z, RCODE;
	private short QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT;
	private byte[] header;

	public DnsHeader(short id, byte qr, byte opcode, byte aa, byte tc, byte rd, byte ra, byte z, byte rcode,
			short qdcount, short ancount, short nscount, short arcount) {
		this.ID = id;
		this.QR = qr;
		this.OPCODE = opcode;
		this.AA = aa;
		this.TC = tc;
		this.RD = rd;
		this.RA = ra;
		this.Z = z;
		this.RCODE = rcode;
		this.QDCOUNT = qdcount;
		this.ANCOUNT = ancount;
		this.NSCOUNT = nscount;
		this.ARCOUNT = arcount;
		this.header = getHeader(this.ID, this.QR, this.OPCODE, this.AA, this.TC, this.RD, this.RA, this.Z, this.RCODE,
				this.QDCOUNT, this.ANCOUNT, this.NSCOUNT, this.ARCOUNT);
	}

	public byte[] getHeader(short id, byte qr, byte opcode, byte aa, byte tc, byte rd, byte ra, byte z, byte rcode,
			short qdcount, short ancount, short nscount, short arcount) {
		byte[] dnsHeader = new byte[12];
		dnsHeader[0] = (byte) (id >>> 8);
		dnsHeader[1] = (byte) (id);
		dnsHeader[2] = (byte) ((qr << 7) | (opcode << 3) | (aa << 2) | (tc << 1) | rd);
		dnsHeader[3] = (byte) ((ra << 7) | (z << 4) | rcode);
		dnsHeader[4] = (byte) (qdcount >>> 8);
		dnsHeader[5] = (byte) (qdcount);
		dnsHeader[6] = (byte) (ancount >>> 8);
		dnsHeader[7] = (byte) (ancount);
		dnsHeader[8] = (byte) (nscount >>> 8);
		dnsHeader[9] = (byte) (nscount);
		dnsHeader[10] = (byte) (arcount >>> 8);
		dnsHeader[11] = (byte) (arcount);
		return dnsHeader;
	}

	public byte[] getHeader() {
		return this.header;
	}

	// Parse the header fields based on the response data.
	public void parseHeader(byte[] header) {
		this.ID = (short) ((header[0] << 8) | header[1]);

		this.QR = (byte) ((header[2] >> 7) & 1);
		if (this.QR == 0) {
			throw new RuntimeException("ERROR\tUnexpected response: this message is not a response.");
		}
		this.OPCODE = (byte) (((header[2] & 0xff) >>> 3) & 0x0f);
		this.AA = (byte) ((header[2] >> 2) & 1);
		this.TC = (byte) ((header[2] >> 1) & 1);
		this.RD = (byte) (header[2] & 1);
		this.RA = (byte) ((header[3] >> 7) & 1);
		this.Z = (byte) (((header[3] & 0xff) >>> 4) & 0x07);
		this.RCODE = (byte) ((header[3] & 0xff) & 0x0f);

		this.QDCOUNT = (short) ((header[4] << 8) | header[5]);
		this.ANCOUNT = (short) ((header[6] << 8) | header[7]);
		this.NSCOUNT = (short) ((header[8] << 8) | header[9]);
		this.ARCOUNT = (short) ((header[10] << 8) | header[11]);
	}

	// Handle the error based on the response code. If code 3 occurs, we output
	// NOTFOUND instead of throwing an error.
	public boolean validateRCode() {
		boolean isCaseThree = false;
		switch (this.RCODE) {
		case 0:
			break;
		case 1:
			throw new RuntimeException("Format error: the name server was unable to interpret the query");
		case 2:
			throw new RuntimeException(
					"Server failure: the name server was unable to process this query due to a problem with the name server");
		case 3:
			isCaseThree = true;
		case 4:
			throw new RuntimeException("Not implemented: the name server does not support the requested kind of query");
		case 5:
			throw new RuntimeException(
					"Refused: the name server refuses to perform the requested operation for policy reasons");
		}
		return isCaseThree;
	}

	public short getANCOUNT() {
		return this.ANCOUNT;
	}

	public short getNSCOUNT() {
		return this.NSCOUNT;
	}

	public short getARCOUNT() {
		return this.ARCOUNT;
	}

	public byte getAA() {
		return this.AA;
	}
}
