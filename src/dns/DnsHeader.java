package dns;

public class DnsHeader {
//	private short ID;
//	private byte QR, OPCODE, AA, TC, RD, RA, Z, RCODE;
//	private short QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT;
	private byte[] header;

	public DnsHeader(short id, byte qr, byte opcode, byte aa, byte tc, byte rd, byte ra, byte z, byte rcode,
			short qdcount, short ancount, short nscount, short arcount) {
//		this.ID = id;
//		this.QR = qr;
//		this.OPCODE = opcode;
//		this.AA = aa;
//		this.TC = tc;
//		this.RD = rd;
//		this.RA = ra;
//		this.Z = z;
//		this.RCODE = rcode;
//		this.QDCOUNT = qdcount;
//		this.ANCOUNT = ancount;
//		this.NSCOUNT = nscount;
//		this.ARCOUNT = arcount;
//		this.header = getHeader(this.ID, this.QR, this.OPCODE, this.AA, this.TC, this.RD, this.RA, this.Z, this.RCODE,
//				this.QDCOUNT, this.ANCOUNT, this.NSCOUNT, this.ARCOUNT);
		this.header = getHeader(id, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount);
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
}
