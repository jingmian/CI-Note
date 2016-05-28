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
 * Permission(权限) is hereby granted(授权), free of charge, to any person obtaining a copy
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
 * Output Class
 *
 * Responsible(管理) for sending final output to the browser.
 *
 * @package		CodeIgniter
 * @subpackage	Libraries
 * @category	Output
 * @author		EllisLab Dev Team
 * @link		https://codeigniter.com/user_guide/libraries/output.html
 */
class CI_Output {

	/**
	 * Final output string
	 * 最终输出字符串
	 *
	 * @var	string
	 */
	public $final_output;

	/**
	 * Cache expiration time
	 * 缓存生命周期
	 *
	 * @var	int
	 */
	public $cache_expiration = 0;

	/**
	 * List of server headers
	 * 服务器头部
	 *
	 * @var	array
	 */
	public $headers = array();

	/**
	 * List of mime types
	 * mine类型列表
	 *
	 * @var	array
	 */
	public $mimes =	array();

	/**
	 * Mime-type for the current page
	 * 当前页面的mime类型
	 *
	 * @var	string
	 */
	protected $mime_type = 'text/html';

	/**
	 * Enable Profiler flag
	 * 是否允许探查标志
	 *
	 * @var	bool
	 */
	public $enable_profiler = FALSE;

	/**
	 * php.ini zlib.output_compression flag
	 * php zlib模块输出压缩标志
	 *
	 * @var	bool
	 */
	protected $_zlib_oc = FALSE;

	/**
	 * CI output compression flag
	 * ci 输出是否启用压缩标志
	 *
	 * @var	bool
	 */
	protected $_compress_output = FALSE;

	/**
	 * List of profiler sections
	 * 探测块列表  ？？？
	 *
	 * @var	array
	 */
	protected $_profiler_sections =	array();

	/**
	 * Parse markers flag
	 * 转换标志标志 ？？？
	 *
	 * Whether or not to parse variables like {elapsed_time} and {memory_usage}.
	 *
	 * @var	bool
	 */
	public $parse_exec_vars = TRUE;

	/**
	 * Class constructor
	 *
	 * Determines whether zLib output compression will be used.
	 *
	 * @return	void
	 */
	public function __construct()
	{
		// php配置中是否开启zlib 压缩功能
		$this->_zlib_oc = (bool) ini_get('zlib.output_compression');
		// 是否开启压缩
		$this->_compress_output = (
			$this->_zlib_oc === FALSE
			&& config_item('compress_output') === TRUE
			&& extension_loaded('zlib')
		);

		// Get mime types for later
		// 获取最新mime类型
		$this->mimes =& get_mimes();

		log_message('info', 'Output Class Initialized');
	}

	// --------------------------------------------------------------------

	/**
	 * Get Output
	 *
	 * Returns the current output string.
	 * 返回当前输出字符串
	 *
	 * @return	string
	 */
	public function get_output()
	{
		return $this->final_output;
	}

	// --------------------------------------------------------------------

	/**
	 * Set Output
	 *
	 * Sets the output string.
	 * 设置输出字符串
	 *
	 * @param	string	$output	Output data
	 * @return	CI_Output
	 */
	public function set_output($output)
	{
		$this->final_output = $output;
		return $this;
	}

	// --------------------------------------------------------------------

	/**
	 * Append Output
	 *
	 * Appends data onto the output string.
	 * 追加数据到输出字符串
	 *
	 * @param	string	$output	Data to append
	 * @return	CI_Output
	 */
	public function append_output($output)
	{
		$this->final_output .= $output;
		return $this;
	}

	// --------------------------------------------------------------------

	/**
	 * Set Header
	 *
	 * Lets you set a server header which will be sent with the final output.
	 * 设置头部
	 *
	 * Note: If a file is cached, headers will not be sent.
	 * note：如果文件在缓存中，头部不会被发送
	 * @todo	We need to figure out how to permit headers to be cached.
	 * 我们需要指出头部是怎么被允许缓存的
	 *
	 * @param	string	$header		Header 头部字符串
	 * @param	bool	$replace	Whether to replace the old header value, if already set 如果存在，是否代替旧的头部
	 * @return	CI_Output
	 */
	public function set_header($header, $replace = TRUE)
	{
		// If zlib.output_compression is enabled it will compress the output,
		// 如果开启了zlib.output_compression，则会压缩输出
		// but it will not modify the content-length header to compensate for
		// the reduction, causing the browser to hang waiting for more data.
		// 但它不会修改内容长度报头，以补偿减少，导致浏览器挂起等待更多的数据。
		// We'll just skip content-length in those cases.
		// 我们只跳过在这种情况下内容长度。

		//　strncasecmp 二进制安全比较字符串开头的若干个字符
		// 开启压缩，而且头部指包含content-length，则直接返回
		if ($this->_zlib_oc && strncasecmp($header, 'content-length', 14) === 0)
		{
			return $this;
		}

		$this->headers[] = array($header, $replace);
		return $this;
	}

	// --------------------------------------------------------------------

	/**
	 * Set Content-Type Header
	 * 设置content-type头部
	 *
	 * @param	string	$mime_type	Extension of the file we're outputting mime类型
	 * @param	string	$charset	Character set (default: NULL) 字符编码
	 * @return	CI_Output
	 */
	public function set_content_type($mime_type, $charset = NULL)
	{
		// 不存在 /
		if (strpos($mime_type, '/') === FALSE)
		{
			// 删除开头的 。 字符
			$extension = ltrim($mime_type, '.');

			// Is this extension supported?
			//　查找mime列表中是否存在改项mime类型
			if (isset($this->mimes[$extension]))
			{
				// 存在
				$mime_type =& $this->mimes[$extension];

				// 如果mime是数组，则获取数组中当前元素作为mime_type设置头部
				if (is_array($mime_type))
				{
					$mime_type = current($mime_type);
				}
			}
		}

		// 设置mime类型
		$this->mime_type = $mime_type;

		// 如果字符编码为空，则获取config配置文件中设置的charset
		if (empty($charset))
		{
			$charset = config_item('charset');
		}

		$header = 'Content-Type: '.$mime_type
			.(empty($charset) ? '' : '; charset='.$charset);

		//如果头部已存在，则用新的替换
		$this->headers[] = array($header, TRUE);
		return $this;
	}

	// --------------------------------------------------------------------

	/**
	 * Get Current Content-Type Header
	 * 获取当前content-type头部
	 *
	 * @return	string	'text/html', if not already set
	 */
	public function get_content_type()
	{
		// 遍历头部
		for ($i = 0, $c = count($this->headers); $i < $c; $i++)
		{
			// 匹配比较
			if (sscanf($this->headers[$i][0], 'Content-Type: %[^;]', $content_type) === 1)
			{
				return $content_type;
			}
		}

		// 返回默认值 text/html
		return 'text/html';
	}

	// --------------------------------------------------------------------

	/**
	 * Get Header
	 * 获取头部
	 *
	 * @param	string	$header_name 头部名称
	 * @return	string
	 */
	public function get_header($header)
	{
		// Combine headers already sent with our batched headers
		// 将已发送和未发送头部合并
		$headers = array_merge(
			// We only need [x][0] from our multi-dimensional array
			// header= array(header,bool), array_shift移除第一个元素header，并返回
			array_map('array_shift', $this->headers),

			// 获取已经发送的头部
			headers_list()
		);

		// 空头部，返回null
		if (empty($headers) OR empty($header))
		{
			return NULL;
		}

		// 遍历头部
		for ($i = 0, $c = count($headers); $i < $c; $i++)
		{
			// 比较
			if (strncasecmp($header, $headers[$i], $l = strlen($header)) === 0)
			{
				// 返回头部
				return trim(substr($headers[$i], $l+1));
			}
		}

		return NULL;
	}

	// --------------------------------------------------------------------

	/**
	 * Set HTTP Status Header
	 * 设置相应状态码
	 *
	 * As of version 1.7.2, this is an alias for common function
	 * set_status_header().
	 *
	 * @param	int	$code	Status code (default: 200) 状态码
	 * @param	string	$text	Optional message 可选 说明文本
	 * @return	CI_Output
	 */
	public function set_status_header($code = 200, $text = '')
	{
		// 调用Common.php文件中定义的set_status_header函数
		set_status_header($code, $text);
		return $this;
	}

	// --------------------------------------------------------------------

	/**
	 * Enable/disable Profiler
	 * 开启/关闭 探查
	 *
	 * @param	bool	$val	TRUE to enable or FALSE to disable
	 * @return	CI_Output
	 */
	public function enable_profiler($val = TRUE)
	{
		$this->enable_profiler = is_bool($val) ? $val : TRUE;
		return $this;
	}

	// --------------------------------------------------------------------

	/**
	 * Set Profiler Sections
	 * 设置探查的部分
	 *
	 * Allows override of default/config settings for
	 * Profiler section display.
	 *
	 * @param	array	$sections	Profiler sections
	 * @return	CI_Output
	 */
	public function set_profiler_sections($sections)
	{
		if (isset($sections['query_toggle_count']))
		{
			$this->_profiler_sections['query_toggle_count'] = (int) $sections['query_toggle_count'];
			unset($sections['query_toggle_count']);
		}

		foreach ($sections as $section => $enable)
		{
			$this->_profiler_sections[$section] = ($enable !== FALSE);
		}

		return $this;
	}

	// --------------------------------------------------------------------

	/**
	 * Set Cache
	 * 设置缓存时间
	 *
	 * @param	int	$time	Cache expiration time in minutes
	 * @return	CI_Output
	 */
	public function cache($time)
	{
		$this->cache_expiration = is_numeric($time) ? $time : 0;
		return $this;
	}

	// --------------------------------------------------------------------

	/**
	 * Display Output
	 *
	 * Processes and sends finalized output data to the browser along
	 * with any server headers and profile data. It also stops benchmark
	 * timers so the page rendering speed and memory usage can be shown.
	 *
	 * Note: All "view" data is automatically put into $this->final_output
	 *	 by controller class.
	 *
	 * @uses	CI_Output::$final_output
	 * @param	string	$output	Output data override
	 * @return	void
	 */
	public function _display($output = '')
	{
		// Note:  We use load_class() because we can't use $CI =& get_instance()
		// since this function is sometimes called by the caching mechanism,
		// which happens before the CI super object is available.
		$BM =& load_class('Benchmark', 'core');
		$CFG =& load_class('Config', 'core');

		// Grab the super object if we can.
		if (class_exists('CI_Controller', FALSE))
		{
			$CI =& get_instance();
		}

		// --------------------------------------------------------------------

		// Set the output data
		if ($output === '')
		{
			$output =& $this->final_output;
		}

		// --------------------------------------------------------------------

		// Do we need to write a cache file? Only if the controller does not have its
		// own _output() method and we are not dealing with a cache file, which we
		// can determine by the existence of the $CI object above
		// 缓存时间大于0，而且ci不存在_output方法
		if ($this->cache_expiration > 0 && isset($CI) && ! method_exists($CI, '_output'))
		{
			// 写入缓存
			$this->_write_cache($output);
		}

		// --------------------------------------------------------------------

		// Parse out the elapsed time and memory usage,
		// then swap the pseudo-variables with the data
		// 解析出所用的时间和内存使用情况，然后交换伪变量与数据
		$elapsed = $BM->elapsed_time('total_execution_time_start', 'total_execution_time_end');

		// 解析变量
		if ($this->parse_exec_vars === TRUE)
		{
			// 使用内存
			$memory	= round(memory_get_usage() / 1024 / 1024, 2).'MB';
			// 替换
			$output = str_replace(array('{elapsed_time}', '{memory_usage}'), array($elapsed, $memory), $output);
		}

		// --------------------------------------------------------------------

		// Is compression requested?
		// 是否是一个压缩请求
		if (isset($CI) // This means that we're not serving a cache file, if we were, it would already be compressed
			&& $this->_compress_output === TRUE
			&& isset($_SERVER['HTTP_ACCEPT_ENCODING']) && strpos($_SERVER['HTTP_ACCEPT_ENCODING'], 'gzip') !== FALSE)
		{
			// ob_start(classback function);
			// 函数将打开输出缓冲。当输出缓冲激活后，脚本将不会输出内容（除http标头外），相反需要输出的内容被存储在内部缓冲区中。

			//　真正发送压缩过的数据之前，
			// 该 函数会确定（判定）浏览器可以接受哪种类型内容编码（"gzip","deflate",或者根本什么都不支持），
			// 然后 返回相应的输出。
			// 所有可以发送正确头信息表明他自己可以接受压缩的网页的浏览器，都可以支持。
			// All browsers are supported since it's up to the browser to send the correct header saying that it accepts compressed web pages.
			// 如果一个浏览器不支持压缩过的页面，此函数返回FALSE。
			ob_start('ob_gzhandler');
		}

		// --------------------------------------------------------------------

		// Are there any server headers to send?
		// 发送头部
		if (count($this->headers) > 0)
		{
			foreach ($this->headers as $header)
			{
				@header($header[0], $header[1]);
			}
		}

		// --------------------------------------------------------------------

		// Does the $CI object exist?
		// If not we know we are dealing with a cache file so we'll
		// simply echo out the data and exit.
		// 如果没有ci对象，我们知道我们面对的是一个缓存文件，然后简单的输出数据，然后退出
		if ( ! isset($CI))
		{
			// 开启压缩
			if ($this->_compress_output === TRUE)
			{
				if (isset($_SERVER['HTTP_ACCEPT_ENCODING']) && strpos($_SERVER['HTTP_ACCEPT_ENCODING'], 'gzip') !== FALSE)
				{
					header('Content-Encoding: gzip');
					header('Content-Length: '.strlen($output));
				}
				else
				{
					// User agent doesn't support gzip compression,
					// so we'll have to decompress our cache
					$output = gzinflate(substr($output, 10, -8));
				}
			}

			echo $output;
			log_message('info', 'Final output sent to browser');
			log_message('debug', 'Total execution time: '.$elapsed);
			return;
		}

		// --------------------------------------------------------------------

		// Do we need to generate profile data?
		// If so, load the Profile class and run it.
		if ($this->enable_profiler === TRUE)
		{
			$CI->load->library('profiler');
			if ( ! empty($this->_profiler_sections))
			{
				$CI->profiler->set_sections($this->_profiler_sections);
			}

			// If the output data contains closing </body> and </html> tags
			// we will remove them and add them back after we insert the profile data
			$output = preg_replace('|</body>.*?</html>|is', '', $output, -1, $count).$CI->profiler->run();
			if ($count > 0)
			{
				$output .= '</body></html>';
			}
		}

		// Does the controller contain a function named _output()?
		// If so send the output there.  Otherwise, echo it.
		if (method_exists($CI, '_output'))
		{
			$CI->_output($output);
		}
		else
		{
			echo $output; // Send it to the browser!
		}

		log_message('info', 'Final output sent to browser');
		log_message('debug', 'Total execution time: '.$elapsed);
	}

	// --------------------------------------------------------------------

	/**
	 * Write Cache
	 * 写入缓存
	 *
	 * @param	string	$output	Output data to cache
	 * @return	void
	 */
	public function _write_cache($output)
	{
		$CI =& get_instance();									// ci实例
		$path = $CI->config->item('cache_path');				// 配置缓存路径
		$cache_path = ($path === '') ? APPPATH.'cache/' : $path;// 最终缓存路径

		//　检查缓存路径
		if ( ! is_dir($cache_path) OR ! is_really_writable($cache_path))
		{
			log_message('error', 'Unable to write cache file: '.$cache_path);
			return;
		}

		// 获取当前页面uri
		$uri = $CI->config->item('base_url')
			.$CI->config->item('index_page')
			.$CI->uri->uri_string();

		if (($cache_query_string = $CI->config->item('cache_query_string')) && ! empty($_SERVER['QUERY_STRING']))
		{
			if (is_array($cache_query_string))
			{
				$uri .= '?'.http_build_query(array_intersect_key($_GET, array_flip($cache_query_string)));
			}
			else
			{
				$uri .= '?'.$_SERVER['QUERY_STRING'];
			}
		}

		// 缓存目录
		$cache_path .= md5($uri);

		// 创建打开文件
		if ( ! $fp = @fopen($cache_path, 'w+b'))
		{
			log_message('error', 'Unable to write cache file: '.$cache_path);
			return;
		}

		// 排他锁锁住文件
		if (flock($fp, LOCK_EX))
		{
			// If output compression is enabled, compress the cache
			// itself, so that we don't have to do that each time
			// we're serving it
			// 开启压缩
			if ($this->_compress_output === TRUE)
			{
				// 压缩输出
				$output = gzencode($output);

				// 设置content-type头部
				if ($this->get_header('content-type') === NULL)
				{
					$this->set_content_type($this->mime_type);
				}
			}

			// 设置过期时间
			$expire = time() + ($this->cache_expiration * 60);

			// Put together our serialized info.
			// 缓存头部信息序列化保存
			$cache_info = serialize(array(
				'expire'	=> $expire,
				'headers'	=> $this->headers
			));

			// 缓存文件格式 缓存信息+'ENDCI--->'+输出内容
			$output = $cache_info.'ENDCI--->'.$output;

			// 写入缓存文件
			for ($written = 0, $length = strlen($output); $written < $length; $written += $result)
			{
				if (($result = fwrite($fp, substr($output, $written))) === FALSE)
				{
					break;
				}
			}

			// 解锁
			flock($fp, LOCK_UN);
		}
		else
		{
			log_message('error', 'Unable to secure a file lock for file at: '.$cache_path);
			return;
		}

		// 关闭文件
		fclose($fp);

		// 写入文件字符长度
		if (is_int($result))
		{
			//　改变缓存文件权限
			chmod($cache_path, 0640);
			log_message('debug', 'Cache file written: '.$cache_path);

			// Send HTTP cache-control headers to browser to match file cache settings.
			// 设置缓存头部
			$this->set_cache_header($_SERVER['REQUEST_TIME'], $expire);
		}
		else
		{
			// 写入失败，删除缓存文件，记录日志
			@unlink($cache_path);
			log_message('error', 'Unable to write the complete cache content at: '.$cache_path);
		}
	}

	// --------------------------------------------------------------------

	/**
	 * Update/serve cached output
	 * 更新 服务器缓存输出
	 *
	 * @uses	CI_Config
	 * @uses	CI_URI
	 *
	 * @param	object	&$CFG	CI_Config class instance
	 * @param	object	&$URI	CI_URI class instance
	 * @return	bool	TRUE on success or FALSE on failure
	 */
	public function _display_cache(&$CFG, &$URI)
	{
		// 缓存路径
		$cache_path = ($CFG->item('cache_path') === '') ? APPPATH.'cache/' : $CFG->item('cache_path');

		// Build the file path. The file name is an MD5 hash of the full URI
		// 安装uri标示缓存文件
		$uri = $CFG->item('base_url').$CFG->item('index_page').$URI->uri_string;

		// 开启查询字符串缓存模式（cach_query_string）而且查询字符串非空
		if (($cache_query_string = $CFG->item('cache_query_string')) && ! empty($_SERVER['QUERY_STRING']))
		{
			if (is_array($cache_query_string))
			{
				$uri .= '?'.http_build_query(array_intersect_key($_GET, array_flip($cache_query_string)));
			}
			else
			{
				$uri .= '?'.$_SERVER['QUERY_STRING'];
			}
		}

		// 缓存文件路径
		$filepath = $cache_path.md5($uri);

		// 检查文件是否存在，是否可以打开
		if ( ! file_exists($filepath) OR ! $fp = @fopen($filepath, 'rb'))
		{
			return FALSE;
		}

		// 以共享锁加锁文件
		flock($fp, LOCK_SH);

		// 读取缓存内容
		$cache = (filesize($filepath) > 0) ? fread($fp, filesize($filepath)) : '';

		// 释放锁
		flock($fp, LOCK_UN);
		// 关闭文件
		fclose($fp);

		// Look for embedded serialized file info.
		// 查找可以序列化文件信息
		if ( ! preg_match('/^(.*)ENDCI--->/', $cache, $match))
		{
			return FALSE;
		}

		// 反序列化获取缓存信息
		$cache_info = unserialize($match[1]);
		// 获取缓存生命时间
		$expire = $cache_info['expire'];

		// 获取最后修改时间
		$last_modified = filemtime($filepath);

		// Has the file expired?
		// 当前请求时间已经大于缓存时间
		if ($_SERVER['REQUEST_TIME'] >= $expire && is_really_writable($cache_path))
		{
			// If so we'll delete it.
			// 删除缓存文件
			@unlink($filepath);
			log_message('debug', 'Cache file has expired. File deleted.');
			return FALSE;
		}
		else
		{
			// Or else send the HTTP cache control headers.
			// 设置缓存头部 最后更改时间，过期时间
			$this->set_cache_header($last_modified, $expire);
		}

		// Add headers from cache file.
		// 添加headers头部
		foreach ($cache_info['headers'] as $header)
		{
			$this->set_header($header[0], $header[1]);
		}

		// Display the cache
		// 输出缓存
		$this->_display(substr($cache, strlen($match[0])));
		log_message('debug', 'Cache file is current. Sending it to browser.');
		return TRUE;
	}

	// --------------------------------------------------------------------

	/**
	 * Delete cache
	 * 删除缓存
	 *
	 * @param	string	$uri	URI string
	 * @return	bool
	 */
	public function delete_cache($uri = '')
	{
		//　获取ci单实例
		$CI =& get_instance();
		// 获取缓存路径
		$cache_path = $CI->config->item('cache_path');
		// 如果获取缓存路径为空，则使用默认路径
		if ($cache_path === '')
		{
			$cache_path = APPPATH.'cache/';
		}

		//如果不是目录，记录错误
		if ( ! is_dir($cache_path))
		{
			log_message('error', 'Unable to find cache path: '.$cache_path);
			return FALSE;
		}

		// 如果uri为空，这获取当前uri
		if (empty($uri))
		{
			// 获取uri
			$uri = $CI->uri->uri_string();

			if (($cache_query_string = $CI->config->item('cache_query_string')) && ! empty($_SERVER['QUERY_STRING']))
			{
				if (is_array($cache_query_string))
				{
					// array_flip  交换数组中的键和值
					// array_intersect_key 求交集key的val
					$uri .= '?'.http_build_query(array_intersect_key($_GET, array_flip($cache_query_string)));
				}
				else
				{
					$uri .= '?'.$_SERVER['QUERY_STRING'];
				}
			}
		}

		// 缓存路径
		$cache_path .= md5($CI->config->item('base_url').$CI->config->item('index_page').ltrim($uri, '/'));

		// 如果存在缓存文件，删除
		if ( ! @unlink($cache_path))
		{
			log_message('error', 'Unable to delete cache file for '.$uri);
			return FALSE;
		}

		return TRUE;
	}

	// --------------------------------------------------------------------

	/**
	 * Set Cache Header
	 * 设置缓存头部
	 *
	 * Set the HTTP headers to match the server-side（服务器端） file cache settings
	 * in order to reduce bandwidth.
	 * 设置缓存，减少带宽
	 *
	 * @param	int	$last_modified	Timestamp of when the page was last modified 最后更改时间
	 * @param	int	$expiration	Timestamp of when should the requested page expire from cache 缓存时间
	 * @return	void
	 */
	public function set_cache_header($last_modified, $expiration)
	{
		//　该请求时间点
		$max_age = $expiration - $_SERVER['REQUEST_TIME'];

		/* 在浏览器第一次请求某一个URL时，服务器端的返回状态会是200，内容是你请求的资源，
		 * 同时有一个Last-Modified的属性标记此文件在服务期端最后被修改的时间，格式类似这样：
		 * Last-Modified: Fri, 12 May 2006 18:53:33 GMT
		 * 客户端第二次请求此URL时，根据 HTTP 协议的规定，浏览器会向服务器传送 If-Modified-Since 报头，
		 * 询问该时间之后文件是否有被修改过：
		 * If-Modified-Since: Fri, 12 May 2006 18:53:33 GMT
		 * 如果服务器端的资源没有变化，则自动返回 HTTP 304 （Not Changed.）状态码，内容为空，这样就节省了传输数据量。
		 */
		if (isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) && $last_modified <= strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']))
		{
			// 文件在此时间段内为修改，返回304
			$this->set_status_header(304);
			exit;
		}
		else
		{
			header('Pragma: public');
			// 缓存时间长度
			header('Cache-Control: max-age='.$max_age.', public');
			// 缓存到expriration时间点
			header('Expires: '.gmdate('D, d M Y H:i:s', $expiration).' GMT');
			//上次修改时间
			header('Last-modified: '.gmdate('D, d M Y H:i:s', $last_modified).' GMT');
		}
	}

}
