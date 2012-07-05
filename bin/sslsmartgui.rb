# Gursev Singh Kalra @ Foundstone(McAfee)
# Please see LICENSE.txt for licensing information

begin
require 'cgi'
require 'net/https'
require 'sslsmartlog'
require 'sslsmartlib'
require 'sslsmartconfig'
require 'sslsmartmisc'
require 'sslsmartcontroller'
rescue LoadError => ex
  raise ex
end

begin
require 'rubygems'
rescue LoadError
end

$log = SSLSmartLog.instance
$conf = SSLSmartConfig.instance


require 'wx'

# IDentifiers for GUI controls
ID_SSLSMART_XML           = 111
ID_SSLSMART_XML_VERBOSE   = 112
ID_SSLSMART_HTML          = 113
ID_SSLSMART_HTML_VERBOSE  = 114
ID_SSLSMART_TEXT          = 115
ID_SSLSMART_TEXT_VERBOSE  = 116

ID_SSLSMART_EXIT      = 117
ID_SSLSMART_CLOSE     = 119
ID_SSLSMART_HELP      = 121


HOST_BUTTON_SIZE          = [100,25]
BUTTON_SIZE               = [100,25]
HOST_CONTROL_SPACING      = 5
HOST_BOX_HEIGHT           = 100
HOST_BOX_WIDTH            = 775
CIPHER_GRID_WIDTH         = 775
CIPHER_GRID_HEIGHT        = 200
HOSTS_PROPORTION          = 1
CIPHER_PROPORTION         = 3
HTML_PROPORTION           = 4
CERT_PROPORTION           = 2

SHOW_HTML                 = 0
SHOW_TEXT                 = 1

GRID_COLS                 = 6
TEST_COL                  = 0
VERSION_COL               = 1
NAME_COL                  = 2
BITS_COL                  = 3
SUPPORTED_COL             = 4
HTTP_COL                  = 5


class SSLSmartFrame < Wx::Frame
  
  include SSLSmartMisc

  ###########################################################
  ##+ Start creation of Menu Bar and corresponding functions
  ###########################################################

  def create_menu_bar
    menu_bar = Wx::MenuBar.new

    # The "file" menu
    menu_file = Wx::Menu.new
    menu_file.append(ID_SSLSMART_HTML         , "Export HTML Report\tCtrl-1"          , "Export HTML Report")
    menu_file.append(ID_SSLSMART_HTML_VERBOSE , "Export Verbose HTML Report\tCtrl-2"  , "Export HTML Report")
    menu_file.append(ID_SSLSMART_XML          , "Export XML Report\tCtrl-3"           , "Export XML Report")
    menu_file.append(ID_SSLSMART_XML_VERBOSE  , "Export Verbose XML Report\tCtrl-4"   , "Export XML Report")
    menu_file.append(ID_SSLSMART_TEXT         , "Export TEXT Report\tCtrl-5"          , "Export Text Report")
    menu_file.append(ID_SSLSMART_TEXT_VERBOSE , "Export Verbose TEXT Report\tCtrl-6"  , "Export Text Report")
    menu_file.append_separator()
    menu_file.append(Wx::ID_EXIT, "E&xit\tAlt-X", "Quit this program")
    menu_bar.append(menu_file, "&File")

    # The "help" menu
    menu_help = Wx::Menu.new
    menu_help.append(ID_SSLSMART_HELP, "SSLSmart Help\tF1", "")
    menu_help.append(Wx::ID_ABOUT,     "About........\tF2", "Show about dialog")
    menu_bar.append(menu_help, "&Help")

    self.menu_bar = menu_bar

    # Set it up to handle menu events using the relevant methods.
    evt_menu(Wx::ID_EXIT     , :on_my_close)
    evt_menu(Wx::ID_ABOUT    , :on_about)
    evt_menu(ID_SSLSMART_HTML)              {|event| create_report(event, :html)}
    evt_menu(ID_SSLSMART_HTML_VERBOSE)      {|event| create_report(event, :htmlv)}#   , :create_verbose_html_report)
    evt_menu(ID_SSLSMART_XML)               {|event| create_report(event, :xml)}
    evt_menu(ID_SSLSMART_XML_VERBOSE)       {|event| create_report(event, :xmlv)}
    evt_menu(ID_SSLSMART_TEXT)              {|event| create_report(event, :text)}
    evt_menu(ID_SSLSMART_TEXT_VERBOSE)      {|event| create_report(event, :textv)}
    evt_menu(ID_SSLSMART_HELP, :show_help)

  end


  ###########################################################
  ##- END Menu Bar and corresponding functions
  ###########################################################


  def write_results_to_file(content, filetype)
    case filetype
    when :html
      append = ".html"
    when :htmlv
      filetype = :html
      append = "_Verbose.html"
    when :text
      append = ".txt"
    when :textv
      filetype  = :txt
      append = "_Verbose.txt"
    when :xml
      append = ".xml"
    when :xmlv
      filetype  = :xml
      append = "_Verbose.xml"
    end

    file_dialog = Wx::FileDialog.new(self, "Export #{filetype.to_s.upcase} Results As", "", "SSLSmart#{append}", "*.*", Wx::FD_SAVE| Wx::FD_OVERWRITE_PROMPT)
    file_dialog.show_modal
    path = file_dialog.get_path
    return if(path == nil || path == "")
    begin
      File.open(path, 'w') do |f|
        f.puts content
      end
    rescue => ex
      $log.error(ex.message)
      Wx::MessageDialog.new(nil, "Error Occured!!\nPlease see log files for more details", "", Wx::OK ).show_modal()
    end
  end


  def create_report(event, type)
    return unless(@controller)
    report_content = @controller.create_report(type)
    write_results_to_file(report_content, type) if(report_content)
  end


  def show_help()
    Wx::MessageDialog.new(nil, "Visit Foundstone website to download SSLSmart white paper", "SSLSmart Help", Wx::OK).show_modal
  end


  def on_my_close()
    rval = Wx::MessageDialog.new(nil, "Are you sure you want to exit?","Exit Confirmation", Wx::ICON_QUESTION|Wx::YES_NO).show_modal
    return if(rval == Wx::ID_NO)
    $log.debug("Exiting SSLSmart")
    destroy
    exit
  end


  def on_about()
    Wx::about_box(:name => self.title,
               :version     => "1.0",
               :description => "For Smart SSL Cipher Enumeration",
               :developers  => ['Gursev Kalra @ Foundstone'] )
  end


  def on_changing_page(event)
    event.veto if(@test_running)
  end

  
  ##+ Creating the two tabs to host all GUI elements
  def create_workspace_and_options_tabs()
    new_notebook           = Wx::Notebook.new(self)

    @ws_tab                 = Wx::Panel.new(new_notebook) # Add workspace tab
    @ws_mvsizer             = Wx::BoxSizer.new(Wx::VERTICAL)
    @ws_tab.set_sizer(@ws_mvsizer)

    @options_tab            = Wx::Panel.new(new_notebook) # Add options tab
    @options_mvsizer        = Wx::BoxSizer.new(Wx::VERTICAL)
    @options_tab.set_sizer(@options_mvsizer)


    new_notebook.add_page(@ws_tab      , "Workspace")
    new_notebook.add_page(@options_tab , "Options")
    evt_notebook_page_changing(new_notebook.get_id())  {|event| on_changing_page(event) }
  end
  
  ##- End of tab creation
  def clear_gui_and_results()
    $log.debug("Clearing GUI and Results")
    return if(@test_running)
    @controller = nil
    ws_clear_results_from_grid()
    $conf.urls.each_index do |i|
      @hosts_listbox.check(i, false)
    end
    @pbar.set_value(0)
    @response_html.set_page("")
    @response_text.set_value("")
    @cert_info.set_value("")
  end


  ###########################################################
  ##+ Begin creating all GUI elements and related functionalities for WorkSheet Tab
  ###########################################################

  def ws_sync_from_conf()
    $log.debug("Synchronizing configuration to GUI")
    choices = {true => "1", false => ""}
    rows    = @ws_cipher_grid.get_number_rows
    0.upto(rows - 1) do |row|
      @ws_cipher_grid.set_cell_value(row, TEST_COL, choices[$conf.cipher_suites[row].test])
    end
  end

  
  def ws_sync_to_conf()
    $log.debug("Synchronizing GUI to configuration")
    choices = {"" => false, "1" => true}
    rows    = @ws_cipher_grid.get_number_rows
    0.upto(rows - 1) do |row|
      cell_val = @ws_cipher_grid.get_cell_value(row, TEST_COL)
      $conf.cipher_suites[row].test   = choices[cell_val]
    end
  end


  def ws_start_test(event)
    return if(@test_running || $conf.urls == [])
    $log.debug("Starting Test")
    @stop_test    = false
    ws_sync_to_conf()
    clear_gui_and_results()
    @test_running = true

    @controller      = SSLSmartController.new
    x = Thread.new do
      $log.debug "Starting test thread"
      begin
        @controller.start_test do |url, url_index, suite_index|
          
          progress = @controller.get_progress(url).to_i
          if(@hosts_listbox.get_string_selection == url)
            ws_populate_one_cipher_result(suite_index, @controller.get_response(url, suite_index)) if(suite_index)
            ws_populate_cert_info(url)
            @pbar.set_value(progress)
          end
          @hosts_listbox.check(url_index) if(progress == 100)
          if(@stop_test)
            @test_running           = false
            $log.warn("Forcibly killed thread")
            Thread.kill(x)
          end
        end
        @test_running           = false
        #@controller.show_results
      rescue => ex
        $log.fatal(ex.message)
        $log.fatal(ex.backtrace)
      ensure
        @test_running           = false
      end
    end

    #event.skip
  end


  def ws_refresh_hosts_listbox(event)
    @hosts_listbox.set($conf.urls)
    event.skip
  end

  
  def ws_add_single_host(event)
    $log.debug("Adding a single host")
    host_entry_box = Wx::TextEntryDialog.new(@ws_mpanel,"", "Add URL/Host to Test")
    retval = host_entry_box.show_modal
    if(retval == Wx::ID_OK)
      #url = SSLMisc.convert_to_url(host_entry_box.get_value)
      url = convert_to_url(host_entry_box.get_value)
      $conf.update_config({:urls => $conf.urls | [url]}) if(url)
      ws_refresh_hosts_listbox(event)
    end
    event.skip
  end

  
  def ws_import_hosts(event)
    $log.debug("Adding a multiple hosts")
    file_control   = Wx::FileDialog.new(@ws_mpanel, "Input File containing host entries (one per line)", "", "", "Text Files (*.txt)|*.txt", Wx::FD_MULTIPLE)
    file_control.show_modal
    file_names   = file_control.get_paths
    file_names.each do |x|
      if(File.file?(x))
        #urls = SSLMisc.get_urls_from_file(x)
        urls = get_urls_from_file(x)
        $conf.update_config({:urls => $conf.urls | urls})
        ws_refresh_hosts_listbox(event)
      end
    end
    event.skip
  end

  
  def ws_rem_hosts(event)
    $log.debug("Removing hosts")

    return if(@test_running)
    arr = @hosts_listbox.get_selections
    arr += @hosts_listbox.get_checked_items
    keep = (0...$conf.urls.length).to_a - arr
    $conf.update_config({:urls => $conf.urls.values_at(*keep)})
    ws_refresh_hosts_listbox(event)
    event.skip
  end
  

  def ws_rem_all_hosts(event)
    $log.debug("Removing all hosts")
    return if(@test_running)
    clear_gui_and_results()
    $conf.update_config({:urls => []})
    ws_refresh_hosts_listbox(event)
    event.skip
  end

  def ws_stop_test(event)
    $log.info("Attempt to stop test")
    @stop_test = true
  end


  def ws_clear_results(event)
    $log.debug("Clearing all results")
    clear_gui_and_results()
    event.skip
  end

  
  def ws_create_buttons(parent_panel, sizer)
    ws_hosts_button_hsizer    = Wx::BoxSizer.new(Wx::HORIZONTAL)    # sizer for hosts button controls

    ws_start_test             = Wx::Button.new(parent_panel, Wx::ID_ANY, "Start Test"           , Wx::DEFAULT_POSITION, HOST_BUTTON_SIZE)
    # Threads should come here
    evt_button(ws_start_test.get_id()) { |event| ws_start_test(event) }

    # Add URL/Host Button and Corresponding event handlers
    ws_add_host               = Wx::Button.new(parent_panel, Wx::ID_ANY, "Add URL/Host"         , Wx::DEFAULT_POSITION, HOST_BUTTON_SIZE)
    evt_button(ws_add_host.get_id()) { |event| ws_add_single_host(event)}

    # Import URL's/Hosts
    ws_import_hosts              = Wx::Button.new(parent_panel, Wx::ID_ANY, "Import URLs/Hosts"    , Wx::DEFAULT_POSITION, HOST_BUTTON_SIZE)
    evt_button(ws_import_hosts.get_id()) { |event| ws_import_hosts(event)}

    # Remove one host
    ws_rem_host               = Wx::Button.new(parent_panel, Wx::ID_ANY, "Remove"               , Wx::DEFAULT_POSITION, HOST_BUTTON_SIZE)
    evt_button(ws_rem_host.get_id()) { |event| ws_rem_hosts(event)}

    # Remove one host
    ws_rem_all_hosts          = Wx::Button.new(parent_panel, Wx::ID_ANY, "Remove All"           , Wx::DEFAULT_POSITION, HOST_BUTTON_SIZE)
    evt_button(ws_rem_all_hosts.get_id()) { |event| ws_rem_all_hosts(event)}

    ws_clear_results         = Wx::Button.new(parent_panel, Wx::ID_ANY, "Clear Results"    , Wx::DEFAULT_POSITION, HOST_BUTTON_SIZE)
    evt_button(ws_clear_results.get_id()) { |event| ws_clear_results(event)}

    ws_stop_test              = Wx::Button.new(parent_panel, Wx::ID_ANY, "Stop Test"        , Wx::DEFAULT_POSITION, HOST_BUTTON_SIZE)
    evt_button(ws_stop_test.get_id()) { |event| ws_stop_test(event)}

    ws_hosts_button_hsizer.add_item(ws_start_test     , -1, 0, Wx::ALL, HOST_CONTROL_SPACING)
    ws_hosts_button_hsizer.add_item(ws_add_host       , -1, 0, Wx::ALL, HOST_CONTROL_SPACING)
    ws_hosts_button_hsizer.add_item(ws_import_hosts   , -1, 0, Wx::ALL, HOST_CONTROL_SPACING)
    ws_hosts_button_hsizer.add_item(ws_rem_host       , -1, 0, Wx::ALL, HOST_CONTROL_SPACING)
    ws_hosts_button_hsizer.add_item(ws_rem_all_hosts  , -1, 0, Wx::ALL, HOST_CONTROL_SPACING)
    ws_hosts_button_hsizer.add_item(ws_clear_results  , -1, 0, Wx::ALL, HOST_CONTROL_SPACING)
    ws_hosts_button_hsizer.add_item(ws_stop_test      , -1, 0, Wx::ALL, HOST_CONTROL_SPACING)

    sizer.add_item(ws_hosts_button_hsizer , -1, 0, Wx::EXPAND|Wx::ALL)

  end

  
  def ws_populate_cipher_result(event)
    @response_html.set_page("")
    @response_text.set_value("")
    return unless(@controller)
    
    @selected_grid_row    = event.get_row
    url             = @hosts_listbox.get_string_selection
    if(url != "")
      html_response   = @controller.get_html_response(url, @selected_grid_row)
      text_response   = @controller.get_text_response(url, @selected_grid_row)

      @response_html.set_page(html_response) if(html_response)
      @response_text.set_value(text_response) if(text_response)
    end
  end


  def ws_populate_cipher_result_for_url(url)
    @response_html.set_page("")
    @response_text.set_value("")
    return unless(@controller)

    if(url != "")
      html_response   = @controller.get_html_response(url, @selected_grid_row)
      text_response   = @controller.get_text_response(url, @selected_grid_row)

      @response_html.set_page(html_response) if(html_response)
      @response_text.set_value(text_response) if(text_response)
    end
  end

  
  def ws_create_cipher_grid(parent_panel, sizer)
    #    TEST_COL                 = 0
    #    VERSION_COL              = 1
    #    NAME_COL                 = 2
    #    BITS_COL                 = 3
    #    SUPPORTED_COL            = 4
    #    HTTP_COL                 = 5

    read_only                     = Wx::GridCellAttr.new
    #read_only.set_read_only
    # Starting the Cipher Grid GUI Code Here
    cipher_hsizer                 = Wx::BoxSizer.new(Wx::HORIZONTAL)  # sizer for ciphers grid

    # @ws_cipher_grid is instance variable because it is going to be needed across functions and entire functionality
    @ws_cipher_grid               = Wx::Grid.new(parent_panel, -1, Wx::DEFAULT_POSITION, [CIPHER_GRID_WIDTH , CIPHER_GRID_HEIGHT])
    #@ws_cipher_grid.auto_size

    @ws_cipher_grid.create_grid($conf.cipher_suites.length, GRID_COLS)
    #@ws_cipher_grid.enable_editing(false)
    #@ws_cipher_grid.disable_cell_edit_control
    @ws_cipher_grid.set_col_label_size(25)
    @ws_cipher_grid.set_row_label_size(25)
    @ws_cipher_grid.set_col_label_value( TEST_COL, "Test?" )
    @ws_cipher_grid.set_col_size( TEST_COL, 35 )

    @ws_cipher_grid.set_col_label_value( VERSION_COL, "SSL Version" )
    @ws_cipher_grid.set_col_attr(VERSION_COL, read_only)

    @ws_cipher_grid.set_col_label_value( NAME_COL, "Cipher Name" )
    @ws_cipher_grid.set_col_size( NAME_COL, 200 )
    @ws_cipher_grid.set_col_attr(NAME_COL, read_only)

    @ws_cipher_grid.set_col_label_value( BITS_COL, "Key Length (bits)" )
    @ws_cipher_grid.set_col_size( BITS_COL, 125 )
    @ws_cipher_grid.set_col_attr(BITS_COL, read_only)

    @ws_cipher_grid.set_col_label_value( SUPPORTED_COL, "Supported?" )
    @ws_cipher_grid.set_col_attr(SUPPORTED_COL, read_only)

    @ws_cipher_grid.set_col_label_value( HTTP_COL, "Response Code" )
    @ws_cipher_grid.set_col_size( HTTP_COL, 180 )
    @ws_cipher_grid.set_col_attr(HTTP_COL, read_only)
    evt_grid_select_cell() {|event| ws_populate_cipher_result(event); event.skip}
    #@ws_cipher_grid.set_selection_mode(Wx::Grid::GridSelectRows)
    #@ws_cipher_grid.can_enable_cell_control
    #populate_grid

    # The below code was needs to be uncommented. ONLY ONE LINE
    #evt_grid_select_cell() {|event| populate_cipher_result_in_html_box(event); event.skip}
    #evt_grid_range_select() {|event| selected(event)}

    cipher_hsizer.add_item(@ws_cipher_grid, -1, 0,  Wx::EXPAND|Wx::ALL)

    sizer.add_item(cipher_hsizer, -1, CIPHER_PROPORTION, Wx::EXPAND|Wx::ALL, HOST_CONTROL_SPACING)
    # Ending the Cipher Grid GUI Code Here

  end

  
  def ws_create_progress_bar(parent_panel, sizer)
    pbar_hsizer   = Wx::BoxSizer.new(Wx::HORIZONTAL)  # sizer for ciphers grid
    @pbar         = Wx::Gauge.new(parent_panel, -1, 100, Wx::DEFAULT_POSITION, [775,20])
    pbar_hsizer.add_item(@pbar, -1, 0,  Wx::EXPAND|Wx::ALL)
    sizer.add_item(pbar_hsizer, -1, 0, Wx::EXPAND|Wx::ALL)
  end

  def ws_html_click(event)
    return
  end
  
  def ws_create_response_display(parent_panel, sizer)
    new_notebook              = Wx::Notebook.new(parent_panel)

    html_tab                  = Wx::Panel.new(new_notebook) # Add HTML display
    html_sizer                = Wx::BoxSizer.new(Wx::HORIZONTAL)
    html_tab.set_sizer(html_sizer)
    @response_html            = Wx::HtmlWindow.new(html_tab, -1, Wx::DEFAULT_POSITION, [CIPHER_GRID_WIDTH - 15, CIPHER_GRID_HEIGHT], Wx::HW_DEFAULT_STYLE, "HtmlWindow")
    html_sizer.add_item(@response_html,  -1, 0, Wx::EXPAND|Wx::ALL, HOST_CONTROL_SPACING)
    evt_html_link_clicked(@response_html.get_id()) { | event | ws_html_click(event) }
    evt_html_cell_clicked(@response_html.get_id()) { | event | ws_html_click(event) }
    
    text_tab                  = Wx::Panel.new(new_notebook) # Add HTML display
    text_sizer                = Wx::BoxSizer.new(Wx::HORIZONTAL)
    text_tab.set_sizer(text_sizer)
    @response_text            = Wx::TextCtrl.new(text_tab, -1, "", Wx::DEFAULT_POSITION, [CIPHER_GRID_WIDTH - 15, CIPHER_GRID_HEIGHT], Wx::TE_READONLY|Wx::TE_MULTILINE, Wx::DEFAULT_VALIDATOR, "TextWindow")
    text_sizer.add_item(@response_text,  -1, 0, Wx::EXPAND|Wx::ALL, HOST_CONTROL_SPACING)

    new_notebook.add_page(html_tab   , "HTML")
    new_notebook.add_page(text_tab   , "Text")
    sizer.add_item(new_notebook, -1, HTML_PROPORTION, Wx::EXPAND|Wx::ALL, HOST_CONTROL_SPACING)
  end


  def ws_create_cert_display(parent_panel, sizer)
    #@cert_info            = Wx::TextCtrl.new(parent_panel, -1, "", Wx::DEFAULT_POSITION, Wx::DEFAULT_SIZE, Wx::TE_READONLY|Wx::TE_MULTILINE|Wx::TE_RICH|Wx::TE_RICH2)
    hsizer                = Wx::BoxSizer.new(Wx::HORIZONTAL)
    @cert_info            = Wx::TextCtrl.new(parent_panel, -1, "", Wx::DEFAULT_POSITION, [CIPHER_GRID_WIDTH, CIPHER_GRID_HEIGHT], Wx::TE_READONLY|Wx::TE_MULTILINE|Wx::TE_RICH|Wx::TE_RICH2)
    hsizer.add_item(@cert_info, -1, 0, Wx::EXPAND|Wx::ALL)
    sizer.add_item(hsizer,  -1, CERT_PROPORTION, Wx::EXPAND|Wx::ALL, HOST_CONTROL_SPACING)

  end

  
  def ws_populate_cert_info(url)
    $log.debug("Populating certificate information")
    @cert_info.set_value("")
    return unless(@controller)
    cert              = @controller.get_cert(url)
    return unless(cert)
    txtattr           = Wx::TextAttr.new(Wx::BLACK)
    cert_validity     = @controller.cert_valid?(url)

    case cert_validity.status
    when true
      txtattr.set_background_colour(Wx::GREEN)
      @cert_info.set_default_style(txtattr)
      @cert_info.append_text("[+] Valid Digital Certificate\n")
    when false
      txtattr.set_background_colour(Wx::RED)
      @cert_info.set_default_style(txtattr)
      @cert_info.append_text("[-] Invalid Digital Certificate. #{cert_validity.data}\n")
    end

    if(cert.data.class == OpenSSL::X509::Certificate)
      @cert_info.append_text(cert.data.to_text)
    else
      @cert_info.append_text(cert.data)
    end
    @cert_info.set_insertion_point(0)
  end

  
  def ws_clear_results_from_grid()
    $log.debug("Clearing all results from cipher grid")
    cipher_count      = $conf.cipher_suites.length
    0.upto(cipher_count - 1) do |index|
        @ws_cipher_grid.set_cell_value(index, SUPPORTED_COL, "")
        @ws_cipher_grid.set_cell_value(index, HTTP_COL, "")
        @ws_cipher_grid.set_cell_background_colour(index, SUPPORTED_COL, Wx::NULL_COLOUR)
    end
  end

  # To be used inside SSLController.start_test
  def ws_populate_one_cipher_result(suite_index, result)
    return unless(result)
    case result.status
    when true
      @ws_cipher_grid.set_cell_value(suite_index, SUPPORTED_COL, "Yes")
      @ws_cipher_grid.set_cell_background_colour(suite_index, SUPPORTED_COL, Wx::GREEN)
      @ws_cipher_grid.set_cell_value(suite_index, HTTP_COL, "HTTP\/#{result.data.http_version} #{result.data.code} #{result.data.msg}") if(result.data)
    when false
      @ws_cipher_grid.set_cell_value(suite_index, SUPPORTED_COL, "No")
      @ws_cipher_grid.set_cell_background_colour(suite_index, SUPPORTED_COL, Wx::RED)
      @ws_cipher_grid.set_cell_value(suite_index, HTTP_COL, "#{result.data}") if(result.data)
    end # end of case
  end


  def ws_populate_host_results(url)
    ws_clear_results_from_grid()
    return unless(@controller)
    cipher_results      = @controller.get_all_cipher_results(url)
    return if(cipher_results == nil || cipher_results == [])
    
    cipher_results.each_with_index do |result, index|
      ws_populate_one_cipher_result(index, result)
#      case result.status
#      when true
#        @ws_cipher_grid.set_cell_value(index, SUPPORTED_COL, "Yes")
#        @ws_cipher_grid.set_cell_background_colour(index, SUPPORTED_COL, Wx::GREEN)
#        @ws_cipher_grid.set_cell_value(index, HTTP_COL, "HTTP\/#{result.data.http_version} #{result.data.code} #{result.data.msg}") if(result.data)
#      when false
#        @ws_cipher_grid.set_cell_value(index, SUPPORTED_COL, "No")
#        @ws_cipher_grid.set_cell_background_colour(index, SUPPORTED_COL, Wx::RED)
#        #@cipher_grid.set_cell_value(index, HTTP_COL, "#{result.data.message}") if(result.data)
#        @ws_cipher_grid.set_cell_value(index, HTTP_COL, "#{result.data}") if(result.data)
#      end # end of case
    end
  end

  
  def ws_populate_progress(url)
    return unless(@controller)
    @pbar.set_value(@controller.get_progress(url).to_i)
  end

  
  def ws_populate_cert_info_and_test_results(url)
    @response_html.set_page("")
    @response_text.set_value("")
    ws_populate_progress(url)
    ws_populate_cipher_result_for_url(url)
    ws_populate_cert_info(url)
    ws_populate_host_results(url)
  end

  
  def ws_create_hosts_control(parent_panel, sizer)
    hosts_hsizer           = Wx::BoxSizer.new(Wx::HORIZONTAL)  # sizer for hosts controls
    @hosts_listbox         = Wx::CheckListBox.new(parent_panel, -1, [10,10], [HOST_BOX_WIDTH,HOST_BOX_HEIGHT])#, ["1","3","4","5"], Wx::TE_READONLY)

    #Uncomment the line below to make it working
    evt_listbox(@hosts_listbox.get_id()) {|event| ws_populate_cert_info_and_test_results(@hosts_listbox.get_string_selection) }

    hosts_hsizer.add_item(@hosts_listbox, -1, 0, Wx::EXPAND|Wx::ALL, HOST_CONTROL_SPACING)
    sizer.add_item(hosts_hsizer        , -1, HOSTS_PROPORTION, Wx::EXPAND|Wx::ALL)
  end

  
  def ws_create_gui(parent_panel, sizer)
    $log.info("Creating WorkSpace GUI Tab")
    ws_create_buttons(parent_panel, sizer)
    ws_create_hosts_control(parent_panel, sizer)
    ws_create_cipher_grid(parent_panel, sizer)
    ws_create_progress_bar(parent_panel, sizer)
    ws_create_response_display(parent_panel, sizer)
    ws_create_cert_display(parent_panel, sizer)
  end

  ###########################################################
  ##+ End of all GUI elements for WorkSheet Tab
  ###########################################################

  ###########################################################
  ##+ Begin creating all GUI elements for Options Tab
  ###########################################################

  def options_update_config(event, hash)
    return if(@test_running)
    $conf.update_config(hash)
    clear_gui_and_results() if(hash.has_key?(:scan_mode) || hash.has_key?(:scan_type) )
    ws_sync_from_conf() if(hash.has_key?(:sslv2) || hash.has_key?(:tlsv1)|| hash.has_key?(:sslv3) )
    event.skip
  end

  
  def options_create_cipher_checkbox(parent_panel, sizer)
    sslv2 = "SSLv2"
    sslv3 = "SSLv3"
    tlsv1 = "TLSv1"
    ssl_hsizer       = Wx::BoxSizer.new(Wx::HORIZONTAL)
    ssl_static_box   = Wx::StaticBox.new(parent_panel, -1, "SSL Cipher Versions To Test")
    ssl_vsizer       = Wx::StaticBoxSizer.new(ssl_static_box, Wx::VERTICAL)


    # IT IS NOT MANDATORY TO HAVE @sslv2, @sslv3 and @tlsv1 as instance variables.
    # LOOK Into possibility of changing these to local variables

    @sslv2    = Wx::CheckBox.new(parent_panel, -1, sslv2)
    @sslv2.set_value($conf.sslv2)
    evt_checkbox(@sslv2.get_id()) { |event| options_update_config(event, {:sslv2 => @sslv2.get_value}) }

    @sslv3    = Wx::CheckBox.new(parent_panel, -1, sslv3)
    @sslv3.set_value($conf.sslv3)
    evt_checkbox(@sslv3.get_id()) { |event| options_update_config(event, {:sslv3 => @sslv3.get_value}) }

    @tlsv1    = Wx::CheckBox.new(parent_panel, -1, tlsv1)
    @tlsv1.set_value($conf.tlsv1)
    evt_checkbox(@tlsv1.get_id()) { |event| options_update_config(event, {:tlsv1 => @tlsv1.get_value}) }

    ssl_vsizer.add_item(@sslv2, -1, 0)
    ssl_vsizer.add_item(@sslv3, -1, 0)
    ssl_vsizer.add_item(@tlsv1, -1, 0)
    #@ws_mvsizer.add_item(@hosts_button_hsizer , -1, 0, Wx::EXPAND|Wx::ALL)

    ssl_hsizer.add_item(ssl_vsizer, -1, 1, Wx::EXPAND|Wx::ALL)
    sizer.add_item(ssl_hsizer, -1, 0, Wx::EXPAND|Wx::ALL, 10)
    
  end


  def options_content_connect_radio(parent_panel, sizer)
    choices = SSLSmartConfig::SCAN_TYPES
    hsizer = Wx::BoxSizer.new(Wx::HORIZONTAL)
    @content_connect = Wx::RadioBox.new(parent_panel, -1, "Perform Content or Connect Test", Wx::DEFAULT_POSITION, Wx::DEFAULT_SIZE, choices)
    evt_radiobox(@content_connect.get_id()) {|event| options_update_config(event, {:scan_type => @content_connect.get_selection})}
    @content_connect.set_string_selection("#{$conf.scan_type}")
    hsizer.add_item(@content_connect, -1, 1, Wx::EXPAND|Wx::ALL)
    sizer.add_item(hsizer, -1, 0, Wx::EXPAND|Wx::ALL, 10)
  end


  def options_suite_version_radio(parent_panel, sizer)
    choices = SSLSmartConfig::SCAN_MODES
    hsizer  = Wx::BoxSizer.new(Wx::HORIZONTAL)
    @scan_mode = Wx::RadioBox.new(parent_panel, -1, "Select Test Option", Wx::DEFAULT_POSITION, Wx::DEFAULT_SIZE, choices)
    evt_radiobox(@scan_mode.get_id()) {|event| options_update_config(event, {:scan_mode => @scan_mode.get_selection}); options_apply_filter(@filter_combo.get_value())}
    #evt_radiobox(@scan_mode.get_id()) {|event| options_update_config(event, {:scan_mode => @scan_mode.get_selection})}
    @scan_mode.set_string_selection("#{$conf.scan_mode}")
    hsizer.add_item(@scan_mode, -1, 1, Wx::EXPAND|Wx::ALL)
    sizer.add_item(hsizer, -1, 0, Wx::EXPAND|Wx::ALL, 10)
  end


  def options_proxy_config(parent_panel, sizer)
    proxy_input      = Wx::StaticBox.new(parent_panel, -1, "Proxy Configuration (Must be a Transparent Proxy)")
    proxy_vsizer     = Wx::StaticBoxSizer.new(proxy_input, Wx::VERTICAL)

    proxy_add_hsizer  = Wx::BoxSizer.new(Wx::HORIZONTAL)
    proxy_port_hsizer  = Wx::BoxSizer.new(Wx::HORIZONTAL)

    proxy_add_tag  =  Wx::StaticText.new(parent_panel, -1, "Proxy Address", Wx::DEFAULT_POSITION, [100,25])
    @proxy_add  = Wx::TextCtrl.new(parent_panel, -1, "", Wx::DEFAULT_POSITION, [150,25])
    evt_text(@proxy_add.get_id()) {|event| options_update_config(event, {:proxy_add => @proxy_add.get_value})}
    proxy_add_hsizer.add_item(proxy_add_tag)
    proxy_add_hsizer.add_item(@proxy_add)

    proxy_port_tag  =  Wx::StaticText.new(parent_panel, -1, "Proxy Port", Wx::DEFAULT_POSITION, [100,25])
    @proxy_port = Wx::TextCtrl.new(parent_panel, -1, "", Wx::DEFAULT_POSITION, [150,25])
    evt_text(@proxy_port.get_id()) {|event| options_update_config(event, {:proxy_port => @proxy_port.get_value})}
    proxy_port_hsizer.add_item(proxy_port_tag)
    proxy_port_hsizer.add_item(@proxy_port)

    proxy_vsizer.add_item(proxy_add_hsizer)
    proxy_vsizer.add_item(proxy_port_hsizer)

    sizer.add_item(proxy_vsizer, -1, 0, Wx::EXPAND|Wx::ALL, 10)
  end


  def options_lookup_pem_file(parent_panel, event)
    $log.debug("Looking up pem file")
    return if(@test_running)
    pem_file_control   = Wx::FileDialog.new(parent_panel, "Choose Pem File with Root CA Certificates", "", "", "Pem Files (*.pem)|*.pem")
    pem_file_control.show_modal
    file_names   = pem_file_control.get_paths
      file_names.each do |x|
        if(File.file?(x))
          @pem_path.set_value(x)
          $conf.update_config({:pem_path => x})
        end
    end
    event.skip
  end
  

  def options_pem_config(parent_panel, sizer)
    pem_input      = Wx::StaticBox.new(parent_panel, -1, "PEM File Selector")
    pem_hsizer     = Wx::StaticBoxSizer.new(pem_input, Wx::HORIZONTAL)

    choose_pem_button       = Wx::Button.new(parent_panel, -1, "Choose Pem File", Wx::DEFAULT_POSITION, BUTTON_SIZE)
    evt_button(choose_pem_button.get_id()) { |event| options_lookup_pem_file(parent_panel, event)}

    @pem_path              = Wx::TextCtrl.new(parent_panel, -1, $conf.rootcert_path, Wx::DEFAULT_POSITION, Wx::DEFAULT_SIZE, Wx::TE_READONLY)

    pem_hsizer.add_item(choose_pem_button)
    pem_hsizer.add_item(@pem_path, -1, 1, Wx::EXPAND|Wx::ALL)

    sizer.add_item(pem_hsizer, -1, 0, Wx::EXPAND|Wx::ALL, 10)
  end


  def options_apply_filter(value)
    return if(@test_running)
    choices     = {true => "1", false => ""}
    clear_gui_and_results() #unless($conf.filter == value)
    
    begin
      $conf.update_config({:filter => value})
    rescue => ex
      Wx::MessageDialog.new(nil, "Error Occured!!\n#{ex.message}", "", Wx::OK ).show_modal()
      $log.error "Error occured. #{ex.message}"
    end
    
    #Resize the grid if required
    if ((diff = ($conf.cipher_suites.length - @ws_cipher_grid.get_number_rows)) >= 0 )
      @ws_cipher_grid.append_rows(diff)
    else
      @ws_cipher_grid.delete_rows(0, diff.abs)
    end

    @ws_cipher_grid.clear_grid()
    $conf.cipher_suites.each_with_index do |cipher_suite, row_number|
      @ws_cipher_grid.set_cell_editor(row_number, TEST_COL   , Wx::GridCellBoolEditor.new)
      @ws_cipher_grid.set_cell_renderer(row_number, TEST_COL , Wx::GridCellBoolRenderer.new)
      @ws_cipher_grid.set_cell_value(row_number, TEST_COL    , choices[cipher_suite.test])
      @ws_cipher_grid.set_cell_value(row_number, VERSION_COL , cipher_suite.version)
      @ws_cipher_grid.set_cell_value(row_number, NAME_COL    , cipher_suite.name.gsub(":",", "))
      @ws_cipher_grid.set_cell_value(row_number, BITS_COL    , cipher_suite.bits)
    end

  end

  
  def options_cipher_filter(parent_panel, sizer)
    filters               = ["DEFAULT", "DEFAULT:!SSLv2", "DEFAULT:!SSLv3", "HIGH","MEDIUM", "LOW", "LOW:EXP", "LOW:EXP:SSLv2", "ALL:eNULL:aNULL", "NULL", "aNULL"]
    filter_input          = Wx::StaticBox.new(parent_panel, -1, "OpenSSL Filters for Cipher Suite Selection ")
    hsizer                = Wx::StaticBoxSizer.new(filter_input, Wx::HORIZONTAL)
    @filter_combo         = Wx::ComboBox.new(parent_panel, -1, "#{filters[0]}", Wx::DEFAULT_POSITION, Wx::DEFAULT_SIZE, filters)
    apply_filter_button   = Wx::Button.new(parent_panel, -1, "Apply Filter", Wx::DEFAULT_POSITION, BUTTON_SIZE)
    
    evt_button(apply_filter_button.get_id()) {|event| options_apply_filter(@filter_combo.get_value())}
    hsizer.add_item(apply_filter_button, -1, 0, Wx::EXPAND|Wx::ALL)
    hsizer.add_item(@filter_combo, -1, 1, Wx::EXPAND|Wx::ALL)
    sizer.add_item(hsizer, -1, 0, Wx::EXPAND|Wx::ALL, 10)
    
  end

  
  def options_create_gui(parent_panel, sizer)
    $log.debug("Creating Options GUI Tab")
    options_create_cipher_checkbox(parent_panel, sizer)
    options_content_connect_radio(parent_panel, sizer)
    options_suite_version_radio(parent_panel, sizer)
    options_proxy_config(parent_panel, sizer)
    options_pem_config(parent_panel, sizer)
    options_cipher_filter(parent_panel, sizer)
  end

  ###########################################################
  ##+ End of all GUI elements for Options Tab
  ###########################################################


  def init_config()
    options_apply_filter("DEFAULT")
  end

  
  def initialize(title,x,y)
    @controller   = nil
    @test_running = false
    @stop_test    = false
    @selected_grid_row = 0
    #@urls       = []
    #super(nil, -1, title, Wx::Point.new(x, y), Wx::Size.new(800, 800),Wx::DEFAULT_FRAME_STYLE & ~ (Wx::RESIZE_BORDER|Wx::RESIZE_BOX|Wx::MAXIMIZE_BOX))
    super(nil, -1, title, Wx::Point.new(x, y), Wx::Size.new(800, 800))


    fs_icon = Wx::Icon.new( File.join( File.expand_path("."), "fs_icon_32.ico"), Wx::BITMAP_TYPE_ICO )
    set_icon(fs_icon)

    create_menu_bar()
    # Start GUI Control Creation
    create_workspace_and_options_tabs()
    ws_create_gui(@ws_tab, @ws_mvsizer)
    evt_close {|event| on_my_close()}
    options_create_gui(@options_tab, @options_mvsizer)
    # End GUI Creation

    init_config()

    timer = Wx::Timer.new(self, Wx::ID_ANY)
    evt_timer(timer.id) {Thread.pass}
    timer.start(10)

  end

end

class SSLSmartGUI < Wx::App
  def on_init()
    x = 50
    y = 50
    frame = SSLSmartFrame.new("SSLSmart", x, y)
    frame.show(true)
  end
end

sslsmart = SSLSmartGUI.new
sslsmart.main_loop
