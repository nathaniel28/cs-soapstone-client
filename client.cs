using System;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Text;

namespace Soapstone {
	// If a NotLoggedInException makes its way up to your code,
	// then you can assume the client already tried to Login()
	// It's then up to you to decide whether or not to re-register
	// Thrown when the server returns a status code of 401
	[Serializable]
	public class NotLoggedInException : Exception {
		public NotLoggedInException() {}
		public NotLoggedInException(string what) : base(what) {}
		public NotLoggedInException(string what, Exception inner) : base(what, inner) {}
	}

	// Don't make any API calls for the next 20 seconds. Exceeding more
	// than 1 API call per second is not sustainable.
	// Please catch this, report to the user,
	// and temporarily block API calls
	// Thrown when the server returns a status code of 429
	[Serializable]
	public class RateLimitException : Exception {
		public RateLimitException() {}
		public RateLimitException(string what) : base(what) {}
		public RateLimitException(string what, Exception inner) : base(what, inner) {}
	}

	// This one is context dependent. It means whatever you just called had
	// content associated with it, but that content was malformed.
	// Recovery is possible, and probably just means throwing out the old
	[Serializable]
	public class ParseException : Exception {
		public ParseException() {}
		public ParseException(string what) : base(what) {}
		public ParseException(string what, Exception inner) : base(what, inner) {}
	}

	// Don't bother trying to recover from this one
	// this means there's a bug in your code or this code
	// You should carefully examine what caused this.
	// Thrown when the server returns a status code of 400
	[Serializable]
	public class BadRequestException : Exception {
		public BadRequestException() {}
		public BadRequestException(string what) : base(what) {}
		public BadRequestException(string what, Exception inner) : base(what, inner) {}
	}

	// This only occurs on a Write API call only
	// It means the user has written so many messages that the server won't
	// save any more of theirs. Report to the user that they must delete
	// one of their messages in order to write one more.
	// Thrown when the server returns a status code of 409
	[Serializable]
	public class TooManyMessagesException : Exception {
		public TooManyMessagesException() {}
		public TooManyMessagesException(string what) : base(what) {}
		public TooManyMessagesException(string what, Exception inner) : base(what, inner) {}
	}

	// The raw Message is probably of no use to you
	// Please pass it to StringDecoder.DecodeMessage
	// Client will have a StringDeocder for you in the member Decoder
	[StructLayout(LayoutKind.Sequential, Pack = 4)]
	public struct Message {
		public uint Id;
		public uint Likes;
		public uint Dislikes;
		public ushort Room;
		public ushort X;
		public ushort Y;
		public ushort Word1;
		public ushort Word2;
		public byte Template1;
		public byte Template2;
		public byte Conjunction;
		private byte pad0, pad1, pad2;

		public Message() {}

		// caller should discard padding if it exists
		public Message(BinaryReader stream) {
			// what happened to read(fd, &s, sizeof(s))?
			Id = stream.ReadUInt32();
			Likes = stream.ReadUInt32();
			Dislikes = stream.ReadUInt32();
			Room = stream.ReadUInt16();
			X = stream.ReadUInt16();
			Y = stream.ReadUInt16();
			Word1 = stream.ReadUInt16();
			Word2 = stream.ReadUInt16();
			Template1 = stream.ReadByte();
			Template2 = stream.ReadByte();
			Conjunction = stream.ReadByte();
		}
	}

	// TODO: name sucks
	// From what I understand, Hollow Knight uses strings to identify rooms
	// Messages require a number to write. So, this can also encode room
	// names to room numbers. Mind the KeyNotFoundException.
	public struct StringDecoder {
		public List<string> Templates;
		public List<string> Conjunctions;
		public List<string> Words;
		public Dictionary<string, ushort> Rooms;

		// may throw IndexOutOfRangeException, which you want to catch for once
		public string DecodeMessage(Message msg) {
			string res = string.Format(Templates[msg.Template1], Words[msg.Word1]);
			if (msg.Conjunction != 255) {
				res += $" {Conjunctions[msg.Conjunction]} {string.Format(Templates[msg.Template2], Words[msg.Word2])}";
			}
			return res;
		}

		// for those too lazy to write Decoder.Words[roomName] :)
		// may throw KeyNotFoundException
		public ushort EncodeRoom(string roomName) {
			return Rooms[roomName];
		}
	}

	// Client is a wrapper to the HTTP API revealed by a soapstone server
	// Construct one with two file paths; one for where it should keep a
	// cache, and one where it should keep user login details. The first
	// thing you should do after construction:
	// var t1 = client.UpdateTable();
	// var t2 = client.LoginOrRegister();
	// await Task.WhenAll(t1, t2);
	// The client is now okay to make API calls that require being logged in
	// Furthermore, the Decoder is ready to decode messages and encode rooms
	// NOTE: if the server changed hosts, please manually update Client.host
	// and Client.publicKey
	public class Client {
		// populated by Register or LoginOrRegister
		// accounts are managed by the Client class, and should not be displayed to the player
		// a new user is registered if no file is found at the given credentialPath
		// take care not to misplace that file once it's created,
		// because once it's gone, so is your ability to log in
		public string? Username { get; private set; }
		public string? Password { get; private set; }

		// populated by Version()
		public uint? ServerVersion { get; private set; }

		// populated by Table()
		public StringDecoder Decoder { get; private set; }

		private readonly string credentialPath;
		private readonly string cachePath;

		private readonly HttpClient client;
		private readonly CookieContainer cookieJar;
		// Is someone else hosting? Better update these!
		private static readonly string host = "https://128.9.29.8";
		private static readonly byte[] publicKey = new byte[] { 48, 130, 5, 221, 48, 130, 3, 197, 160, 3, 2, 1, 2, 2, 20, 80, 172, 138, 94, 122, 114, 250, 123, 183, 95, 53, 222, 220, 213, 45, 204, 157, 22, 164, 82, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 126, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12, 10, 67, 97, 108, 105, 102, 111, 114, 110, 105, 97, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 76, 111, 115, 32, 65, 110, 103, 101, 108, 101, 115, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 73, 110, 100, 105, 118, 105, 100, 117, 97, 108, 49, 19, 48, 17, 6, 3, 85, 4, 11, 12, 10, 73, 110, 100, 105, 118, 105, 100, 117, 97, 108, 49, 26, 48, 24, 6, 3, 85, 4, 3, 12, 17, 80, 114, 111, 106, 101, 99, 116, 32, 83, 111, 97, 112, 115, 116, 111, 110, 101, 48, 30, 23, 13, 50, 52, 49, 48, 51, 49, 50, 49, 49, 52, 48, 57, 90, 23, 13, 51, 52, 49, 48, 50, 57, 50, 49, 49, 52, 48, 57, 90, 48, 126, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12, 10, 67, 97, 108, 105, 102, 111, 114, 110, 105, 97, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 76, 111, 115, 32, 65, 110, 103, 101, 108, 101, 115, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 73, 110, 100, 105, 118, 105, 100, 117, 97, 108, 49, 19, 48, 17, 6, 3, 85, 4, 11, 12, 10, 73, 110, 100, 105, 118, 105, 100, 117, 97, 108, 49, 26, 48, 24, 6, 3, 85, 4, 3, 12, 17, 80, 114, 111, 106, 101, 99, 116, 32, 83, 111, 97, 112, 115, 116, 111, 110, 101, 48, 130, 2, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 2, 15, 0, 48, 130, 2, 10, 2, 130, 2, 1, 0, 189, 16, 173, 116, 132, 107, 251, 95, 127, 28, 123, 118, 189, 186, 48, 236, 148, 254, 34, 200, 144, 225, 102, 29, 169, 2, 72, 186, 237, 249, 228, 187, 248, 128, 23, 126, 104, 122, 102, 184, 77, 207, 166, 101, 133, 67, 68, 166, 226, 84, 126, 96, 174, 211, 101, 35, 26, 34, 217, 202, 143, 152, 167, 71, 158, 56, 48, 42, 136, 193, 63, 73, 235, 31, 250, 53, 161, 183, 217, 158, 47, 248, 108, 238, 54, 159, 16, 51, 182, 27, 112, 69, 47, 177, 26, 204, 197, 31, 71, 168, 179, 48, 192, 161, 65, 201, 33, 207, 127, 107, 210, 47, 36, 223, 19, 246, 42, 169, 58, 183, 224, 81, 231, 154, 227, 81, 143, 212, 16, 150, 124, 167, 172, 167, 187, 210, 37, 55, 11, 119, 84, 184, 132, 209, 8, 182, 171, 7, 200, 206, 70, 225, 3, 181, 186, 90, 130, 201, 214, 234, 45, 202, 40, 215, 83, 136, 177, 212, 186, 90, 25, 57, 233, 176, 103, 36, 153, 86, 209, 199, 215, 4, 114, 109, 125, 125, 188, 149, 69, 134, 110, 58, 12, 27, 224, 126, 137, 197, 178, 107, 151, 205, 77, 124, 104, 176, 209, 67, 100, 126, 159, 133, 65, 108, 230, 46, 105, 179, 242, 107, 253, 232, 149, 73, 244, 109, 112, 99, 209, 62, 253, 3, 37, 20, 200, 5, 235, 104, 139, 186, 132, 107, 162, 60, 5, 180, 203, 10, 52, 65, 99, 97, 1, 152, 56, 92, 124, 157, 105, 29, 161, 251, 187, 119, 65, 27, 68, 152, 244, 212, 224, 173, 45, 145, 215, 65, 23, 6, 192, 124, 131, 52, 62, 230, 176, 212, 221, 10, 75, 224, 105, 165, 14, 166, 170, 151, 203, 199, 14, 10, 94, 36, 31, 165, 147, 185, 236, 86, 129, 79, 207, 121, 40, 247, 107, 111, 224, 177, 72, 139, 165, 57, 140, 69, 216, 145, 162, 72, 230, 153, 18, 103, 117, 63, 192, 77, 9, 84, 165, 101, 134, 194, 39, 17, 162, 82, 222, 194, 203, 100, 197, 2, 253, 41, 225, 152, 124, 146, 95, 114, 178, 64, 130, 202, 204, 8, 101, 42, 21, 84, 178, 190, 199, 12, 241, 196, 164, 35, 77, 157, 82, 48, 107, 229, 240, 103, 181, 194, 50, 85, 61, 127, 47, 178, 69, 143, 200, 48, 178, 40, 171, 32, 153, 225, 151, 62, 63, 52, 157, 229, 48, 143, 239, 238, 196, 135, 111, 102, 214, 94, 67, 34, 221, 147, 157, 233, 108, 59, 184, 107, 95, 133, 183, 187, 249, 13, 95, 217, 184, 83, 2, 12, 65, 75, 169, 68, 244, 161, 84, 31, 197, 96, 4, 124, 232, 37, 71, 143, 175, 147, 61, 130, 31, 165, 203, 143, 100, 162, 37, 199, 219, 106, 97, 32, 185, 173, 98, 192, 96, 88, 225, 197, 6, 242, 26, 28, 245, 34, 43, 77, 113, 232, 255, 105, 91, 213, 196, 40, 183, 98, 121, 130, 236, 54, 73, 229, 62, 87, 182, 204, 82, 135, 2, 3, 1, 0, 1, 163, 83, 48, 81, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 125, 57, 108, 237, 96, 208, 58, 71, 112, 44, 89, 201, 36, 124, 21, 71, 56, 77, 75, 96, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 125, 57, 108, 237, 96, 208, 58, 71, 112, 44, 89, 201, 36, 124, 21, 71, 56, 77, 75, 96, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 2, 1, 0, 153, 112, 98, 182, 18, 32, 236, 250, 175, 163, 127, 209, 24, 112, 129, 61, 107, 93, 236, 242, 92, 71, 240, 73, 53, 75, 14, 119, 154, 171, 42, 86, 83, 229, 231, 52, 161, 154, 2, 61, 182, 5, 38, 152, 14, 180, 219, 84, 25, 85, 98, 118, 31, 133, 106, 10, 209, 63, 220, 222, 128, 187, 251, 232, 173, 121, 89, 72, 96, 136, 56, 232, 80, 85, 96, 76, 0, 141, 119, 17, 108, 249, 83, 150, 209, 86, 239, 47, 233, 36, 146, 250, 58, 148, 13, 84, 250, 190, 128, 162, 40, 97, 115, 70, 9, 103, 81, 172, 12, 120, 65, 180, 87, 38, 88, 8, 244, 134, 162, 15, 236, 61, 209, 211, 139, 29, 2, 17, 121, 112, 26, 253, 132, 97, 120, 31, 223, 10, 98, 11, 235, 35, 78, 131, 48, 49, 150, 99, 42, 212, 20, 236, 149, 241, 162, 165, 35, 154, 16, 106, 89, 180, 161, 242, 128, 104, 193, 221, 225, 51, 215, 146, 132, 62, 87, 201, 70, 236, 247, 217, 44, 68, 71, 33, 243, 17, 67, 49, 12, 104, 186, 79, 40, 213, 75, 132, 146, 163, 88, 57, 118, 143, 245, 117, 225, 102, 114, 130, 106, 32, 216, 239, 212, 123, 231, 49, 11, 122, 99, 226, 48, 57, 239, 118, 151, 217, 254, 81, 173, 60, 233, 52, 56, 164, 209, 248, 197, 251, 168, 76, 0, 47, 5, 1, 99, 167, 63, 244, 215, 62, 50, 213, 167, 224, 165, 136, 163, 231, 215, 143, 208, 105, 156, 223, 221, 166, 64, 227, 48, 231, 60, 152, 2, 171, 69, 158, 207, 130, 131, 57, 37, 200, 59, 20, 171, 190, 213, 50, 210, 188, 34, 153, 64, 193, 31, 205, 170, 89, 54, 209, 239, 93, 146, 76, 96, 246, 214, 121, 44, 35, 225, 28, 132, 153, 153, 102, 209, 127, 61, 201, 90, 185, 58, 184, 41, 112, 247, 94, 88, 245, 198, 5, 34, 147, 54, 203, 204, 171, 39, 66, 93, 98, 210, 226, 136, 67, 105, 252, 204, 203, 249, 158, 144, 199, 87, 41, 185, 13, 167, 99, 131, 124, 107, 142, 76, 73, 223, 97, 61, 106, 23, 145, 236, 13, 24, 119, 141, 39, 47, 250, 81, 176, 84, 182, 188, 23, 27, 37, 227, 162, 253, 159, 239, 23, 63, 100, 252, 199, 238, 136, 244, 189, 139, 143, 20, 159, 240, 119, 94, 116, 203, 154, 45, 229, 26, 191, 62, 169, 101, 135, 31, 210, 103, 159, 80, 170, 39, 1, 12, 60, 151, 100, 53, 202, 86, 57, 183, 138, 56, 208, 99, 131, 7, 72, 185, 150, 215, 207, 93, 227, 11, 23, 116, 143, 156, 91, 11, 76, 4, 42, 217, 177, 7, 205, 154, 92, 107, 218, 109, 153, 168, 221, 125, 98, 111, 0, 24, 56, 150, 67, 158, 106, 106, 217, 48, 194, 54, 220, 76, 81, 202, 136, 207, 156, 121, 74, 3, 246, 55, 151, 193, 169, 133, 215, 15, 209, 125, 4, 240, 141, 34, 79 };

		// may throw a ParseException if the file at _credentialPath is invalid
		public Client(string _credentialPath, string _cachePath) {
			credentialPath = _credentialPath;
			cachePath = _cachePath;
			if (File.Exists(credentialPath)) {
				using (var stream = new StreamReader(File.OpenRead(credentialPath))) {
					string? line = stream.ReadLine();
					if (line != null && line.Length >= 3 && line.Length <= 64) {
						Username = line;
					} else {
						throw new ParseException("Invalid stored username.");
					}
					line = stream.ReadLine();
					if (line != null && line.Length >= 8 && line.Length <= 72) {
						Password = line;
					} else {
						throw new ParseException("Invalid stored password.");
					}
				}
			}
			cookieJar = new CookieContainer();
			var handler = new HttpClientHandler {
				CookieContainer = cookieJar,
				UseCookies = true,
				// Accept self-signed certificates given the hardcoded public key
				ServerCertificateCustomValidationCallback = (HttpRequestMessage req, X509Certificate2? cert, X509Chain? chain, SslPolicyErrors sslPolicyErrors) => {
					if (cert == null) {
						return false;
					}
					var now = DateTime.UtcNow;
					return cert.NotBefore < now && cert.NotAfter > now && cert.RawData.SequenceEqual(Client.publicKey);
				}
			};
			client = new HttpClient(handler) {
				BaseAddress = new Uri(host)
			};
		}

		static private void ensureSuccess(HttpStatusCode status) {
			switch (status) {
				case HttpStatusCode.OK:
					return;
				case HttpStatusCode.BadRequest:
					throw new BadRequestException();
				case HttpStatusCode.TooManyRequests:
					throw new RateLimitException();
				case HttpStatusCode.Unauthorized:
					throw new NotLoggedInException();
				default:
					throw new Exception($"Fatal status code {status}.");
			}
		}

		private void writeUser() {
			using (var stream = new StreamWriter(File.Create(credentialPath))) {
				stream.WriteLine(Username!);
				stream.WriteLine(Password!);
			}
		}

		private StringDecoder parseTable(StreamReader stream) {
			var encoding = new List<string>[3] {
				new List<string>(),
				new List<string>(),
				new List<string>()
			};
			int pos = 0;
			string? line;
			while ((line = stream.ReadLine()) != null) {
				if (line.Length == 0) {
					if (++pos >= encoding.Length) {
						break;
					}
					continue;
				}
				encoding[pos].Add(line);
			}
			ushort u = 0;
			var rdict = new Dictionary<string, ushort>();
			while ((line = stream.ReadLine()) != null) {
				rdict[line] = u++;
			}
			return new StringDecoder {
				Templates = encoding[0],
				Conjunctions = encoding[1],
				Words = encoding[2],
				Rooms = rdict
			};

		}

		private void writeCache() {
			using (var stream = new StreamWriter(File.Create(cachePath))) {
				stream.Write($"{ServerVersion}\n");
				for (int i = 0; i < Decoder.Templates.Count; i++) {
					stream.WriteLine(Decoder.Templates[i]);
				}
				stream.WriteLine();
				for (int i = 0; i < Decoder.Conjunctions.Count; i++) {
					stream.WriteLine(Decoder.Conjunctions[i]);
				}
				stream.WriteLine();
				for (int i = 0; i < Decoder.Words.Count; i++) {
					stream.WriteLine(Decoder.Words[i]);
				}
				var buf = new string[Decoder.Rooms.Count];
				foreach (var kv in Decoder.Rooms) {
					buf[kv.Value] = kv.Key;
				}
				stream.WriteLine();
				for (int i = 0; i < buf.Length; i++) {
					stream.WriteLine(buf[i]);
				}
			}
		}

		private void readCache(uint version) {
			using (var stream = new StreamReader(File.OpenRead(cachePath))) {
				string? line = stream.ReadLine();
				if (line == null) {
					throw new ParseException("Invalid cache.");
				}
				uint requiredVersion = Convert.ToUInt32(line);
				if (requiredVersion != version) {
					throw new ParseException("Invalid version.");
				}
				Decoder = parseTable(stream);
			}
		}

		public async Task UpdateTable() {
			uint v = await Version();
			try {
				readCache(v);
				return;
			} catch (Exception e) {
				Console.WriteLine($"Bad cache: {e.Message}\nCreating a new cache at {cachePath}");
				// cache was invalid, outdated, or nonexistant
				// in any case, ask the server for an updated Decoder
				await Table();
				writeCache();
			}
		}

		// C# wrappers for API calls to follow
		// All can throw many things. Please carefully read the comment
		// above each to know what you should catch and handle.
		// Additionally, all can throw RateLimitException.
		// On an uncrecoverable error, the optimal solution is to report
		// it to the user and shut down the mod, but keep the game alive
		// NOTE: Yes, you should catch and handle KeyNotFoundException,
		// for example, if the user has mods with new rooms it will be
		// thrown when they enter one.

		// Throws nothing you can recover from.
		public async Task<uint> Version() {
			HttpResponseMessage resp = await client.GetAsync("/version");
			ensureSuccess(resp.StatusCode);
			using (var stream = await resp.Content.ReadAsStreamAsync()) {
				var buf = new byte[4];
				if (await stream.ReadAsync(buf, 0, buf.Length) != buf.Length) {
					throw new ParseException("Server response is too short.");
				}
				uint res = BitConverter.ToUInt32(buf, 0);
				ServerVersion = res;
				return res;
			}
		}

		// Throws nothing you can recover from.
		public async Task Table() {
			HttpResponseMessage resp = await client.GetAsync("/table");
			ensureSuccess(resp.StatusCode);
			using (var stream = new StreamReader(await resp.Content.ReadAsStreamAsync())) {
				StringDecoder decoder = parseTable(stream);
				for (int i = 0; i < decoder.Templates.Count; i++) {
					decoder.Templates[i] = decoder.Templates[i].Replace("%s", "{0}");
				}
				Decoder = decoder;
			}
		}

		// Throws NotLoggedInException if the credentials provided are
		// invalid. This is a pretty dire error. The fix is probably
		// deleting the current account and creating a new one. Call
		// Register() to to achieve this. The user should be notified
		// before action is taken on their account.
		// NOTE: You should not call this function unless you **really**
		// know what you're doing. LoginOrRegister() is what you're
		// probably looking for.
		public async Task Login() {
			HttpResponseMessage resp = await client.GetAsync($"/login?name={Uri.EscapeDataString(Username!)}&password={Uri.EscapeDataString(Password!)}");
			ensureSuccess(resp.StatusCode);
		}

		// This interally handles username/password creation.
		// Throws nothing you can recover from.
		// Still can throw unrecoverable errors.
		// NOTE: This function will overwrite the current account!
		// NOTE: You should not call this function unless you **really**
		// know what you're doing. LoginOrRegister() is what you're
		// probably looking for.
		public async Task Register() {
			using (var rng = RandomNumberGenerator.Create()) {
				int triesLeft = 20;
				while (true) {
					// we'll use the first 20 for the password, and the last for the username
					var buf = new byte[40];
					rng.GetBytes(buf);
					// yes, this makes it slightly less random, but not less secure
					for (int i = 0; i < buf.Length; i++) {
						buf[i] = (byte) (32 + buf[i] % 95);
					}
					Username = Encoding.ASCII.GetString(buf, 0, 20);
					Password = Encoding.ASCII.GetString(buf, 20, 20);
					HttpResponseMessage resp = await client.GetAsync($"/register?name={Uri.EscapeDataString(Username)}&password={Uri.EscapeDataString(Password)}");
					if (resp.StatusCode == HttpStatusCode.OK)
						break;
					if (resp.StatusCode == HttpStatusCode.Conflict) {
						if (triesLeft-- == 0)
							throw new Exception("Too many failed attempts to register.");
					} else {
						// let's throw something
						ensureSuccess(resp.StatusCode);
					}
				}
				writeUser();
			}
		}

		// Handle what Login() can throw
		public async Task LoginOrRegister() {
			// Username and Password may have been set by the constructor
			if (Username == null) {
				await Register();
			}
			await Login();
		}

		// Throws KeyNotFoundException given an unsupported roomName.
		// Throw TooManyMessagesException if the server is not willing
		// to save any more of this user's messages. This should be
		// reported to the user.
		public async Task Write(string roomName, ushort x, ushort y, byte template1, ushort word1, byte conjunction, byte template2, ushort word2) {
			string q = $"/write?room={Decoder.EncodeRoom(roomName)}&x={x}&y={y}&t1={template1}&w1={word1}";
			if (conjunction != 255) {
				q += $"&c={conjunction}&t2={template2}&w2={word2}";
			}
			HttpResponseMessage resp = await client.GetAsync(q);
			switch (resp.StatusCode) {
				case HttpStatusCode.OK:
					return;
				case HttpStatusCode.Unauthorized:
					// our token may be expired; try logging in then try again
					await Login();
					resp = await client.GetAsync(q);
					if (resp.StatusCode != HttpStatusCode.OK)
						goto default;
					break; // if break is required why is implicit fallthrough disallowed? C# is weird
				case HttpStatusCode.Conflict:
					throw new TooManyMessagesException();
				default:
					throw new Exception($"Fatal status code {resp.StatusCode}.");
			}
		}

		// See the other Write method for what to handle
		public async Task Write(string roomName, ushort x, ushort y, byte template1, ushort word1) {
			await Write(roomName, x, y, template1, word1, 255, 0, 0);
		}

		private async Task<List<Message>> fromMessageStream(string queryString) {
			HttpResponseMessage resp = await client.GetAsync(queryString);
			ensureSuccess(resp.StatusCode);
			var res = new List<Message>();
			using (var stream = new BinaryReader(await resp.Content.ReadAsStreamAsync())) {
				while (true) {
					try {
						res.Add(new Message(stream));
						// discard padding-- see API docs for why
						stream.ReadByte();
						stream.ReadByte();
						stream.ReadByte();
					} catch (EndOfStreamException) {
						break;
					}
				}
			}
			return res;
		}

		// Throws KeyNotFoundException given an unsupported roomName.
		public async Task<List<Message>> Query(string roomName) {
			return await fromMessageStream($"/query?room={Decoder.EncodeRoom(roomName)}");
		}

		// Throws nothing you can recover from.
		public async Task<List<Message>> Mine() {
			try {
				return await fromMessageStream("/mine");
			} catch (NotLoggedInException) {
				await Login();
				return await fromMessageStream("/mine");
			}
		}

		// Throws nothing you can recover from.
		// Make sure to supply an id of a message you wrote (you can
		// see everything you wrote with Mine()).
		public async Task Erase(uint id) {
			HttpResponseMessage resp = await client.GetAsync($"/erase?id={id}");
			try {
				ensureSuccess(resp.StatusCode);
			} catch (NotLoggedInException) {
				resp = await client.GetAsync($"/erase?id={id}");
				ensureSuccess(resp.StatusCode);
			}
		}
	}
}
