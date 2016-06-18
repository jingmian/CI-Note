<?php
/**
 * CodeIgniter
 *
 * An open source application development framework for PHP
 *
 * This content is released under the MIT License (MIT)
 *
 * Copyright (c) 2014 - 2016, British Columbia Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @package	CodeIgniter
 * @author	EllisLab Dev Team
 * @copyright	Copyright (c) 2008 - 2014, EllisLab, Inc. (https://ellislab.com/)
 * @copyright	Copyright (c) 2014 - 2016, British Columbia Institute of Technology (http://bcit.ca/)
 * @license	http://opensource.org/licenses/MIT	MIT License
 * @link	https://codeigniter.com
 * @since	Version 1.0.0
 * @filesource
 */
defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * Input Class
 *
 * Pre-processes global input data for security
 *
 * @package		CodeIgniter
 * @subpackage	Libraries
 * @category	Input
 * @author		EllisLab Dev Team
 * @link		https://codeigniter.com/user_guide/libraries/input.html
 */
class CI_Input {

	/**
	 * IP address of the current user
	 *
	 * @var	string
	 */
	// 当前用户ip
	protected $ip_address = FALSE;

	/**
	 * Allow GET array flag
	 *
	 * If set to FALSE, then $_GET will be set to an empty array.
	 *
	 * @var	bool
	 */
	// 是否允许使用GET数组
	protected $_allow_get_array = TRUE;

	/**
	 * Standardize new lines flag
	 *
	 * If set to TRUE, then newlines are standardized.
	 *
	 * @var	bool
	 */
	// 标准换行符
	protected $_standardize_newlines;

	/**
	 * Enable XSS flag
	 *
	 * Determines whether the XSS filter is always active when
	 * GET, POST or COOKIE data is encountered.
	 * Set automatically based on config setting.
	 *
	 * @var	bool
	 */
	// 是否开启xxs过滤
	protected $_enable_xss = FALSE;

	/**
	 * Enable CSRF flag
	 *
	 * Enables a CSRF cookie token to be set.
	 * Set automatically based on config setting.
	 *
	 * @var	bool
	 */
	// 是否开启csrf
	protected $_enable_csrf = FALSE;

	/**
	 * List of all HTTP request headers
	 *
	 * @var array
	 */
	// http 请求头
	protected $headers = array();

	/**
	 * Raw input stream data
	 *
	 * Holds a cache of php://input contents
	 *
	 * @var	string
	 */
	// raw数据
	protected $_raw_input_stream;

	/**
	 * Parsed input stream data
	 *
	 * Parsed from php://input at runtime
	 *
	 * @see	CI_Input::input_stream()
	 * @var	array
	 */
	// 转化input stream data
	protected $_input_stream;

	// 安全类
	protected $security;
	// utf8类
	protected $uni;

	// --------------------------------------------------------------------

	/**
	 * Class constructor
	 *
	 * Determines whether to globally enable the XSS processing
	 * and whether to allow the $_GET array.
	 *
	 * @return	void
	 */
	public function __construct()
	{
		$this->_allow_get_array		= (config_item('allow_get_array') === TRUE);	// 是否允许使用get数组
		$this->_enable_xss		= (config_item('global_xss_filtering') === TRUE);	// 是否开启xss过滤
		$this->_enable_csrf		= (config_item('csrf_protection') === TRUE);		// 是否开启csrf过滤
		$this->_standardize_newlines	= (bool) config_item('standardize_newlines');	// 是否开启标准换行

		// 加载安全类
		$this->security =& load_class('Security', 'core');

		// Do we need the UTF-8 class?
		// 加载utf8
		if (UTF8_ENABLED === TRUE)
		{
			$this->uni =& load_class('Utf8', 'core');
		}

		// Sanitize global arrays
		// 消除全局检查变量数据
		$this->_sanitize_globals();

		// CSRF Protection check
		// 验证 csrf，如果csrf是激活状态
		if ($this->_enable_csrf === TRUE && ! is_cli())
		{
			$this->security->csrf_verify();
		}

		log_message('info', 'Input Class Initialized');
	}

	// --------------------------------------------------------------------

	/**
	 * Fetch from array 变量数组
	 *
	 * Internal method used to retrieve（检索） values from global arrays. 检索全局数组的内部方法
	 *
	 * @param	array	&$array		$_GET, $_POST, $_COOKIE, $_SERVER, etc.
	 * @param	mixed	$index		Index for item to be fetched from $array 索引
	 * @param	bool	$xss_clean	Whether to apply XSS filtering 是否使用xss过滤
	 * @return	mixed
	 */
	protected function _fetch_from_array(&$array, $index = NULL, $xss_clean = NULL)
	{
		// OR 如果前面条件成立，则直接跳过后面掉语句 - -！

		// 是否使用xss过滤
		is_bool($xss_clean) OR $xss_clean = $this->_enable_xss;

		// If $index is NULL, it means that the whole $array is requested
		// 如果索引是空 则获取整个数组全局变量
		isset($index) OR $index = array_keys($array);

		// allow fetching multiple keys at once
		if (is_array($index))
		{
			$output = array();
			// 遍历
			foreach ($index as $key)
			{
				// 逐步调用
				$output[$key] = $this->_fetch_from_array($array, $key, $xss_clean);
			}

			return $output;
		}

		// (?:pattern)
		// 非获取匹配，匹配pattern但不获取匹配结果，不进行存储供以后使用。
		// 这在使用或字符“(|)”来组合一个模式的各个部分是很有用。
		// 例如“industr(?:y|ies)”就是一个比“industry|industries”更简略的表达式。

		if (isset($array[$index]))
		{
			// 获取索引对应的值
			$value = $array[$index];
		}
		elseif (($count = preg_match_all('/(?:^[^\[]+)|\[[^]]*\]/', $index, $matches)) > 1) // Does the index contain array notation
		{
			// 这是设呢情况下进入？？？
			$value = $array;
			for ($i = 0; $i < $count; $i++)
			{
				$key = trim($matches[0][$i], '[]');
				if ($key === '') // Empty notation will return the value as array
				{
					break;
				}

				if (isset($value[$key]))
				{
					$value = $value[$key];
				}
				else
				{
					return NULL;
				}
			}
		}
		else
		{
			// 不存在，返回null
			return NULL;
		}

		return ($xss_clean === TRUE)
			? $this->security->xss_clean($value)
			: $value;
	}

	// --------------------------------------------------------------------

	/**
	 * Fetch an item from the GET array 获取get数组变量
	 *
	 * @param	mixed	$index		Index for item to be fetched from $_GET 下标
	 * @param	bool	$xss_clean	Whether to apply XSS filtering 是否使用xss过滤
	 * @return	mixed
	 */
	public function get($index = NULL, $xss_clean = NULL)
	{
		return $this->_fetch_from_array($_GET, $index, $xss_clean);
	}

	// --------------------------------------------------------------------

	/**
	 * Fetch an item from the POST array 获取post数组
	 *
	 * @param	mixed	$index		Index for item to be fetched from $_POST
	 * @param	bool	$xss_clean	Whether to apply XSS filtering
	 * @return	mixed
	 */
	public function post($index = NULL, $xss_clean = NULL)
	{
		return $this->_fetch_from_array($_POST, $index, $xss_clean);
	}

	// --------------------------------------------------------------------

	/**
	 * Fetch an item from POST data with fallback to GET 获取post、get数组
	 *
	 * @param	string	$index		Index for item to be fetched from $_POST or $_GET
	 * @param	bool	$xss_clean	Whether to apply XSS filtering
	 * @return	mixed
	 */
	public function post_get($index, $xss_clean = NULL)
	{
		return isset($_POST[$index])
			? $this->post($index, $xss_clean)
			: $this->get($index, $xss_clean);
	}

	// --------------------------------------------------------------------

	/**
	 * Fetch an item from GET data with fallback to POST 获取get post数组
	 *
	 * @param	string	$index		Index for item to be fetched from $_GET or $_POST
	 * @param	bool	$xss_clean	Whether to apply XSS filtering
	 * @return	mixed
	 */
	public function get_post($index, $xss_clean = NULL)
	{
		return isset($_GET[$index])
			? $this->get($index, $xss_clean)
			: $this->post($index, $xss_clean);
	}

	// --------------------------------------------------------------------

	/**
	 * Fetch an item from the COOKIE array 获取cookie
	 *
	 * @param	mixed	$index		Index for item to be fetched from $_COOKIE
	 * @param	bool	$xss_clean	Whether to apply XSS filtering
	 * @return	mixed
	 */
	public function cookie($index = NULL, $xss_clean = NULL)
	{
		return $this->_fetch_from_array($_COOKIE, $index, $xss_clean);
	}

	// --------------------------------------------------------------------

	/**
	 * Fetch an item from the SERVER array 获取server
	 *
	 * @param	mixed	$index		Index for item to be fetched from $_SERVER
	 * @param	bool	$xss_clean	Whether to apply XSS filtering
	 * @return	mixed
	 */
	public function server($index, $xss_clean = NULL)
	{
		return $this->_fetch_from_array($_SERVER, $index, $xss_clean);
	}

	// ------------------------------------------------------------------------

	/**
	 * Fetch an item from the php://input stream
	 * php://input stream 可以获取原始的post数据，但是不能用于multipart/form-data类型的post
	 * 更多信息，参考 http://www.nowamagic.net/academy/detail/12220520
	 *
	 * Useful when you need to access PUT, DELETE or PATCH request data.
	 *
	 * @param	string	$index		Index for item to be fetched
	 * @param	bool	$xss_clean	Whether to apply XSS filtering
	 * @return	mixed
	 */
	public function input_stream($index = NULL, $xss_clean = NULL)
	{
		// Prior(之前) to PHP 5.6, the input stream can only be read once,
		// 5.6之前，input stream只可以读取一次
		// so we'll need to check if we have already done that first.
		// 所以我们需要检查如果我们已经做过一次了
		if ( ! is_array($this->_input_stream))
		{
			// $this->raw_input_stream will trigger __get().
			// raw_input_stream 会触发__get()

			// parse_str将字符串解析成多个变量
			// 将raw_input_steam 转化成变量，并保存到input_stream数组中
			parse_str($this->raw_input_stream, $this->_input_stream);
			is_array($this->_input_stream) OR $this->_input_stream = array();
		}

		return $this->_fetch_from_array($this->_input_stream, $index, $xss_clean);
	}

	// ------------------------------------------------------------------------

	/**
	 * Set cookie
	 * 设置cookie
	 *
	 * Accepts an arbitrary（任意） number of parameters (up to 7) or an associative
	 * array in the first parameter containing all the values.
	 *
	 * @param	string|mixed[]	$name		Cookie name or an array containing parameters 名称或者包含全部参数数组
	 * @param	string		$value		Cookie value 值
	 * @param	int		$expire		Cookie expiration time in seconds 存活时间
	 * @param	string		$domain		Cookie domain (e.g.: '.yourdomain.com') 域名
	 * @param	string		$path		Cookie path (default: '/') 路径
	 * @param	string		$prefix		Cookie name prefix 前缀
	 * @param	bool		$secure		Whether to only transfer cookies via SSL 是否只在ssl下传输
	 * @param	bool		$httponly	Whether to only makes the cookie accessible via HTTP (no javascript) 是否只允许通过http访问cookie
	 * @return	void
	 */
	public function set_cookie($name, $value = '', $expire = '', $domain = '', $path = '/', $prefix = '', $secure = FALSE, $httponly = FALSE)
	{
		// 数组，则解析数组到各个变量中
		if (is_array($name))
		{
			// always leave 'name' in last place, as the loop will break otherwise, due to $$item
			foreach (array('value', 'expire', 'domain', 'path', 'prefix', 'secure', 'httponly', 'name') as $item)
			{
				if (isset($name[$item]))
				{
					$$item = $name[$item];
				}
			}
		}

		//　前缀
		if ($prefix === '' && config_item('cookie_prefix') !== '')
		{
			$prefix = config_item('cookie_prefix');
		}

		// 域名
		if ($domain == '' && config_item('cookie_domain') != '')
		{
			$domain = config_item('cookie_domain');
		}

		//路径
		if ($path === '/' && config_item('cookie_path') !== '/')
		{
			$path = config_item('cookie_path');
		}

		// 是否只在ssl下传输
		if ($secure === FALSE && config_item('cookie_secure') === TRUE)
		{
			$secure = config_item('cookie_secure');
		}

		// 是否只允许通过http访问cookie，如果设置true，脚本（如JavaScript）访问不了cookie
		if ($httponly === FALSE && config_item('cookie_httponly') !== FALSE)
		{
			$httponly = config_item('cookie_httponly');
		}

		// 生存时间
		if ( ! is_numeric($expire))
		{
			$expire = time() - 86500;
		}
		else
		{
			$expire = ($expire > 0) ? time() + $expire : 0;
		}

		// 调用内置php函数设置cookie
		setcookie($prefix.$name, $value, $expire, $path, $domain, $secure, $httponly);
	}

	// --------------------------------------------------------------------

	/**
	 * Fetch the IP Address
	 * 获取用户ip地址
	 * Determines and validates the visitor's IP address.
	 *
	 * @return	string	IP address
	 */
	// ??????????????????????????????????????????????????
	public function ip_address()
	{
		// 已经获取 ，直接返回
		if ($this->ip_address !== FALSE)
		{
			return $this->ip_address;
		}

		// 代理ip，逗号分隔开
		$proxy_ips = config_item('proxy_ips');
		if ( ! empty($proxy_ips) && ! is_array($proxy_ips))
		{
			$proxy_ips = explode(',', str_replace(' ', '', $proxy_ips));
		}

		// 通过server中remote_addr获取ip
		$this->ip_address = $this->server('REMOTE_ADDR');

		if ($proxy_ips)
		{
			// 如果代理服务器ip不为空情况下

			// 遍历 HTTP_X_FORWARDED_FOR、HTTP_CLIENT_IP、HTTP_X_CLIENT_IP、HTTP_X_CLUSTER_CLIENT_IP
			foreach (array('HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'HTTP_X_CLIENT_IP', 'HTTP_X_CLUSTER_CLIENT_IP') as $header)
			{
				if (($spoof = $this->server($header)) !== NULL)
				{
					// Some proxies typically list the whole chain of IP
					// addresses through which the client has reached us.
					// e.g. client_ip, proxy_ip1, proxy_ip2, etc.
					sscanf($spoof, '%[^,]', $spoof);

					if ( ! $this->valid_ip($spoof))
					{
						$spoof = NULL;
					}
					else
					{
						break;
					}
				}
			}

			if ($spoof)
			{
				for ($i = 0, $c = count($proxy_ips); $i < $c; $i++)
				{
					// Check if we have an IP address or a subnet
					if (strpos($proxy_ips[$i], '/') === FALSE)
					{
						// An IP address (and not a subnet) is specified.
						// We can compare right away.
						if ($proxy_ips[$i] === $this->ip_address)
						{
							$this->ip_address = $spoof;
							break;
						}

						continue;
					}

					// We have a subnet ... now the heavy lifting begins
					isset($separator) OR $separator = $this->valid_ip($this->ip_address, 'ipv6') ? ':' : '.';

					// If the proxy entry doesn't match the IP protocol - skip it
					if (strpos($proxy_ips[$i], $separator) === FALSE)
					{
						continue;
					}

					// Convert the REMOTE_ADDR IP address to binary, if needed
					if ( ! isset($ip, $sprintf))
					{
						if ($separator === ':')
						{
							// Make sure we're have the "full" IPv6 format
							$ip = explode(':',
								str_replace('::',
									str_repeat(':', 9 - substr_count($this->ip_address, ':')),
									$this->ip_address
								)
							);

							for ($j = 0; $j < 8; $j++)
							{
								$ip[$j] = intval($ip[$j], 16);
							}

							$sprintf = '%016b%016b%016b%016b%016b%016b%016b%016b';
						}
						else
						{
							$ip = explode('.', $this->ip_address);
							$sprintf = '%08b%08b%08b%08b';
						}

						$ip = vsprintf($sprintf, $ip);
					}

					// Split the netmask length off the network address
					sscanf($proxy_ips[$i], '%[^/]/%d', $netaddr, $masklen);

					// Again, an IPv6 address is most likely in a compressed form
					if ($separator === ':')
					{
						$netaddr = explode(':', str_replace('::', str_repeat(':', 9 - substr_count($netaddr, ':')), $netaddr));
						for ($i = 0; $i < 8; $i++)
						{
							$netaddr[$i] = intval($netaddr[$i], 16);
						}
					}
					else
					{
						$netaddr = explode('.', $netaddr);
					}

					// Convert to binary and finally compare
					if (strncmp($ip, vsprintf($sprintf, $netaddr), $masklen) === 0)
					{
						$this->ip_address = $spoof;
						break;
					}
				}
			}
		}

		if ( ! $this->valid_ip($this->ip_address))
		{
			return $this->ip_address = '0.0.0.0';
		}

		return $this->ip_address;
	}

	// --------------------------------------------------------------------

	/**
	 * Validate IP Address
	 *
	 * @param	string	$ip	IP address
	 * @param	string	$which	IP protocol: 'ipv4' or 'ipv6'
	 * @return	bool
	 */
	// 验证ip地址是否有效
	public function valid_ip($ip, $which = '')
	{
		switch (strtolower($which))
		{
			case 'ipv4':
				$which = FILTER_FLAG_IPV4;
				break;
			case 'ipv6':
				$which = FILTER_FLAG_IPV6;
				break;
			default:
				$which = NULL;
				break;
		}
		// php 内置验证数据函数
		return (bool) filter_var($ip, FILTER_VALIDATE_IP, $which);
	}

	// --------------------------------------------------------------------

	/**
	 * Fetch User Agent string
	 *
	 * @return	string|null	User Agent string or NULL if it doesn't exist
	 */
	// 对ua进行xss过滤
	public function user_agent($xss_clean = NULL)
	{
		return $this->_fetch_from_array($_SERVER, 'HTTP_USER_AGENT', $xss_clean);
	}

	// --------------------------------------------------------------------

	/**
	 * Sanitize Globals
	 * 消除全局变量
	 *
	 * Internal method serving for the following purposes:
	 *
	 *	- Unsets $_GET data, if query strings are not enabled 如果不允许get数组，则消除get数组
	 *	- Cleans POST, COOKIE and SERVER data 检查 post，cookie，server数据
	 * 	- Standardizes newline characters to PHP_EOL 使用php_eol换行
	 *
	 * @return	void
	 */
	protected function _sanitize_globals()
	{
		// Is $_GET data allowed? If not we'll set the $_GET to an empty array
		if ($this->_allow_get_array === FALSE)
		{
			// 关闭get数组，
			$_GET = array();
		}
		elseif (is_array($_GET))
		{
			// 变量get数据，检查是否有恶意字符
			foreach ($_GET as $key => $val)
			{
				// 清楚key 或者 val中恶意字符
				$_GET[$this->_clean_input_keys($key)] = $this->_clean_input_data($val);
			}
		}

		// Clean $_POST Data
		if (is_array($_POST))
		{
			// 变量post
			foreach ($_POST as $key => $val)
			{
				// 调用_clean_input_key 和 _clean_input_data 检查数据
				$_POST[$this->_clean_input_keys($key)] = $this->_clean_input_data($val);
			}
		}

		// Clean $_COOKIE Data
		if (is_array($_COOKIE))
		{
			// Also get rid of specially treated cookies that might be set by a server
			// or silly application, that are of no use to a CI application anyway
			// but that when present will trip our 'Disallowed Key Characters' alarm
			// http://www.ietf.org/rfc/rfc2109.txt
			// note that the key names below are single quoted strings, and are not PHP variables
			unset(
				$_COOKIE['$Version'],
				$_COOKIE['$Path'],
				$_COOKIE['$Domain']
			);

			foreach ($_COOKIE as $key => $val)
			{
				if (($cookie_key = $this->_clean_input_keys($key)) !== FALSE)
				{
					$_COOKIE[$cookie_key] = $this->_clean_input_data($val);
				}
				else
				{
					unset($_COOKIE[$key]);
				}
			}
		}

		// Sanitize PHP_SELF
		// 剥去字符串中的 HTML、XML 以及 PHP 的标签
		$_SERVER['PHP_SELF'] = strip_tags($_SERVER['PHP_SELF']);

		log_message('info', 'Global POST, GET and COOKIE data sanitized');
	}

	// --------------------------------------------------------------------

	/**
	 * Clean Input Data 检查input数据
	 *
	 * Internal method that aids in escaping data and
	 * standardizing newline characters to PHP_EOL.
	 *
	 * @param	string|string[]	$str	Input string(s)
	 * @return	string
	 */
	protected function _clean_input_data($str)
	{
		// 数组
		if (is_array($str))
		{
			$new_array = array();
			// 变量数组
			foreach (array_keys($str) as $key)
			{
				// 调用函数检查过滤数据
				$new_array[$this->_clean_input_keys($key)] = $this->_clean_input_data($str[$key]);
			}
			return $new_array;
		}

		/* We strip slashes if magic quotes is on to keep things consistent

		   NOTE: In PHP 5.4 get_magic_quotes_gpc() will always return 0 and
		         it will probably not exist in future（未来） versions at all.
		*/
		// 小于5.4版本，而且开启magic_quotes_gpc
		if ( ! is_php('5.4') && get_magic_quotes_gpc())
		{
			// 反引用一个引用字符串
			$str = stripslashes($str);
		}

		// Clean UTF-8 if supported
		if (UTF8_ENABLED === TRUE)
		{
			// 使用utf8检查清理
			$str = $this->uni->clean_string($str);
		}

		// Remove control characters
		// 移除无效字符
		$str = remove_invisible_characters($str, FALSE);

		// Standardize newlines if needed
		// 使用标准换行
		if ($this->_standardize_newlines === TRUE)
		{
			return preg_replace('/(?:\r\n|[\r\n])/', PHP_EOL, $str);
		}

		return $str;
	}

	// --------------------------------------------------------------------

	/**
	 * Clean Keys 清理key，允许key存在 a-z0-9:_/|-
	 *
	 * Internal method that helps to prevent malicious(恶意) users
	 * from trying to exploit(利用) keys we make sure that keys are
	 * only named with alpha-numeric text and a few other items.
	 *
	 * @param	string	$str	Input string
	 * @param	bool	$fatal	Whether to terminate script exection 遇到无效key，是否终止脚本或者返回false
	 *				or to return FALSE if an invalid
	 *				key is encountered
	 * @return	string|bool
	 */
	protected function _clean_input_keys($str, $fatal = TRUE)
	{
		if ( ! preg_match('/^[a-z0-9:_\/|-]+$/i', $str))
		{
			// 返回
			if ($fatal === TRUE)
			{
				return FALSE;
			}
			else
			{
				// 终止脚本
				set_status_header(503);
				echo 'Disallowed Key Characters.';
				exit(7); // EXIT_USER_INPUT
			}
		}

		// Clean UTF-8 if supported
		if (UTF8_ENABLED === TRUE)
		{
			return $this->uni->clean_string($str);
		}

		return $str;
	}

	// --------------------------------------------------------------------

	/**
	 * Request Headers
	 *
	 * @param	bool	$xss_clean	Whether to apply XSS filtering
	 * @return	array
	 */
	// 请求头部
	public function request_headers($xss_clean = FALSE)
	{
		// If header is already defined, return it immediately
		// 已经存在
		if ( ! empty($this->headers))
		{
			return $this->headers;
		}

		// In Apache, you can simply call apache_request_headers()
		// 在 apache 环境下，可以使用 apache_request_headers 获取全部 HTTP 请求头信息
		if (function_exists('apache_request_headers'))
		{
			return $this->headers = apache_request_headers();
		}

		$this->headers['Content-Type'] = isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : @getenv('CONTENT_TYPE');

		foreach ($_SERVER as $key => $val)
		{
			// 变量server，寻找http_开头的变量，并保存到header中
			if (sscanf($key, 'HTTP_%s', $header) === 1)
			{
				// take SOME_HEADER and turn it into Some-Header
				$header = str_replace('_', ' ', strtolower($header)); // 将字符串中每个单词的首字母转换为大写
				$header = str_replace(' ', '-', ucwords($header));

				// 获取server中key对应的值
				$this->headers[$header] = $this->_fetch_from_array($_SERVER, $key, $xss_clean);
			}
		}

		return $this->headers;
	}

	// --------------------------------------------------------------------

	/**
	 * Get Request Header
	 *
	 * Returns the value of a single member of the headers class member
	 *
	 * @param	string		$index		Header name
	 * @param	bool		$xss_clean	Whether to apply XSS filtering
	 * @return	string|null	The requested header on success or NULL on failure
	 */
	// 获取请求头部
	public function get_request_header($index, $xss_clean = FALSE)
	{
		static $headers;

		//　如果不存在，则获取headers
		if ( ! isset($headers))
		{
			empty($this->headers) && $this->request_headers();
			foreach ($this->headers as $key => $value)
			{
				$headers[strtolower($key)] = $value;
			}
		}

		// 格式化index
		$index = strtolower($index);

		// 不存在该key对应的val，返回null
		if ( ! isset($headers[$index]))
		{
			return NULL;
		}

		// 如果开启xss，则过滤xss，然后在返回val
		return ($xss_clean === TRUE)
			? $this->security->xss_clean($headers[$index])
			: $headers[$index];
	}

	// --------------------------------------------------------------------

	/**
	 * Is AJAX request?
	 *
	 * Test to see if a request contains the HTTP_X_REQUESTED_WITH header.
	 *
	 * @return 	bool
	 */
	// 是否为ajax请求
	public function is_ajax_request()
	{
		return ( ! empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest');
	}

	// --------------------------------------------------------------------

	/**
	 * Is CLI request?
	 *
	 * Test to see if a request was made from the command line.
	 *
	 * @deprecated	3.0.0	Use is_cli() instead
	 * @return	bool
	 */
	// 是否为cli请求
	public function is_cli_request()
	{
		return is_cli();
	}

	// --------------------------------------------------------------------

	/**
	 * Get Request Method
	 *
	 * Return the request method
	 *
	 * @param	bool	$upper	Whether to return in upper or lower case
	 *				(default: FALSE)
	 * @return 	string
	 */
	// 获取请求方法
	public function method($upper = FALSE)
	{
		return ($upper)
			? strtoupper($this->server('REQUEST_METHOD'))
			: strtolower($this->server('REQUEST_METHOD'));
	}

	// ------------------------------------------------------------------------

	/**
	 * Magic __get() 魔术方法，get
	 *
	 * Allows read access to protected properties
	 *
	 * @param	string	$name
	 * @return	mixed
	 */
	public function __get($name)
	{
		if ($name === 'raw_input_stream')
		{
			//如果存在了_raw_input_steam 则跳过，否则使用file_get_contents('php://input')读取
			isset($this->_raw_input_stream) OR $this->_raw_input_stream = file_get_contents('php://input');
			return $this->_raw_input_stream;
		}
		elseif ($name === 'ip_address')
		{
			// 返回客户ip
			return $this->ip_address;
		}
	}

}
