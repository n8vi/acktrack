Imports System.Net
Imports System.Net.Sockets
Imports System.Text
Imports System.Runtime.InteropServices


Module Module1

    <DllImport("pcapsocket.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function capsck_create_fromstrings(ByVal LocalEndPointStr As String, ByVal RemoteEndPointStr As String) As IntPtr
    End Function
    <DllImport("pcapsocket.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function capsck_isfinished(ByVal cs As IntPtr) As Boolean
    End Function
    <DllImport("pcapsocket.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function capsck_next(capsck As IntPtr) As IntPtr
    End Function
    <DllImport("pcapsocket.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function capsck_se_ts_sec(ByVal se As IntPtr) As Integer
    End Function
    <DllImport("pcapsocket.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function capsck_se_ts_usec(ByVal se As IntPtr) As Integer
    End Function
    <DllImport("pcapsocket.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function capsck_se_is_local(ByVal se As IntPtr) As Boolean
    End Function
    <DllImport("pcapsocket.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function capsck_se_seqno(ByVal se As IntPtr) As Integer
    End Function
    <DllImport("pcapsocket.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function capsck_se_is_interesting(ByVal se As IntPtr) As Boolean
    End Function
    <DllImport("pcapsocket.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function capsck_se_is_error(ByVal se As IntPtr) As Boolean
    End Function

    ' string result = String.Format("{0,10:D6} {0,10:X8}", value);

    Sub printpkt(se As IntPtr)
        If capsck_se_is_interesting(se) Then
            If capsck_se_is_local(se) Then
                Console.WriteLine(String.Format(" --> SEQ {0:D}.{1:D6} {2}", capsck_se_ts_sec(se), capsck_se_ts_usec(se), capsck_se_seqno(se)))
            Else
                Console.WriteLine(String.Format(" <-- ACK {0:D}.{1:D6} {2}", capsck_se_ts_sec(se), capsck_se_ts_usec(se), capsck_se_seqno(se)))
            End If
        End If
    End Sub


    Sub Main()
        Dim socket As Socket
        Dim port As Int32 = 80
        Dim host As String = "google.com"
        Dim request As String = "GET /" + vbNewLine
        Dim bytesReceived() As Byte
        Dim bytesSent() As Byte = Encoding.ASCII.GetBytes(request)
        Dim cs As IntPtr
        Dim se As IntPtr
        Dim utcnow = DateTime.UtcNow
        Dim span As TimeSpan

        socket = createSocket(host, port)

        cs = capsck_create_fromstrings(socket.LocalEndPoint.ToString(), socket.RemoteEndPoint.ToString())

        If socket IsNot Nothing Then
            Console.WriteLine("Socket connected!")

            socket.Send(bytesSent, bytesSent.Length, 0)

            Console.WriteLine("sent bytes.")

            While Not capsck_isfinished(cs)
                se = capsck_next(cs)
                printpkt(se)
                span = DateTime.UtcNow - utcnow
                If socket.Connected And (span > TimeSpan.FromSeconds(3)) Then
                    showRx(socket)
                    Console.WriteLine("Closing socket")
                    socket.Close()
                End If
            End While
        Else
            Console.WriteLine("Socket not connected.")
        End If
        Console.WriteLine("Connection terminated.  Press key to exit.")
        Console.ReadKey()

    End Sub

    Public Function createSocket(ByVal server As String, ByVal port As Int32) As Socket
        Dim hostEntry As IPHostEntry
        Try
            hostEntry = Dns.GetHostEntry(server)
        Catch e As SocketException
            Console.WriteLine("host not found")
            Return Nothing
        End Try

        For Each ipaddress In hostEntry.AddressList
            Dim ipe As IPEndPoint = New IPEndPoint(ipaddress, port)
            Dim sock As Socket = New Socket(ipe.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            sock.Connect(ipe)

            If sock.Connected Then
                Return sock
            Else
                Return Nothing
            End If
        Next
    End Function

    Public Sub showRx(sock As Socket)
        Dim len As Integer
        Dim inBytes() As Byte

        len = sock.Available()
        ReDim inBytes(len)
        Console.Write(len)
        Console.WriteLine(" bytes received.")
        sock.Receive(inBytes, SocketFlags.None)
    End Sub

End Module
