
is_sqlite <- function(path) {
  is.character(path) && file.exists(path) && grepl(pattern = "\\.sqlite$", x = path)
}

is_dbi <- function(con) {
  inherits(con, "DBIConnection")
}

hasName <- function(x, name) {
  match(name, names(x), nomatch = 0L) > 0L
}

get_appname <- function() {
  getOption("shinymanager.application", default = basename(getwd()))
}

get_args <- function(..., fun) {
  args_fun <- names(formals(fun))
  args <- list(...)
  args[names(args) %in% args_fun]
}

# Check whether the backend is a SQL or SQLite database
is_database <- function() {
  return(!is.null(.tok$get_sqlite_path()) | !is.null(.tok$get_dbi_con()))
}

#' @importFrom RSQLite SQLite
#' @importFrom DBI dbConnect
get_conn <- function() {
  conn = NULL
  sqlite_path <- .tok$get_sqlite_path()
  dbi_conn = .tok$get_dbi_con()
  if (!is.null(sqlite_path)) {
    conn <- dbConnect(SQLite(), dbname = sqlite_path)
  } else if (!is.null(.tok$get_dbi_con())) {
    conn = dbi_conn
  }
  return(conn)
}

#' Close the connection if it's an SQLite connection
#' @importFrom DBI dbDisconnect
close_conn <- function(conn) {
  sqlite_path <- .tok$get_sqlite_path()
  if (!is.null(sqlite_path)) {
    dbDisconnect(conn)
  }
}

#' @importFrom R.utils capitalize
make_title <- function(x) {
  capitalize(gsub(
    pattern = "_", replacement = " ", x = x
  ))
}

dropFalse <- function(x) {
  isFALSE <- Negate(isTRUE)
  x[!vapply(x, isFALSE, FUN.VALUE = logical(1))]
}

#' @importFrom RSQLite SQLite
is_force_chg_pwd <- function(token) {
  user_info <- .tok$get(token)
  conn = get_conn()
  on.exit(close_conn(conn))
  passphrase <- .tok$get_passphrase()
  if (!is.null(conn)) {
    resetpwd <- read_db_decrypt(conn, name = "pwd_mngt", passphrase = passphrase)
    ind_user <- resetpwd$user %in% user_info$user
    identical(resetpwd$must_change[ind_user], "TRUE")
  } else {
    return(FALSE)
  }
}

#' @importFrom RSQLite SQLite
force_chg_pwd <- function(user, change = TRUE) {
  conn = get_conn()
  on.exit(close_conn(conn))
  passphrase <- .tok$get_passphrase()
  if (!is.null(conn)) {
    resetpwd <- read_db_decrypt(conn, name = "pwd_mngt", passphrase = passphrase)
    ind_user <- resetpwd$user %in% user
    resetpwd$must_change[ind_user] <- change
    if (!isTRUE(change)) {
      resetpwd$have_changed[ind_user] <- TRUE
      resetpwd$date_change[ind_user] <- as.character(Sys.Date())
    }
    write_db_encrypt(conn, value = resetpwd, name = "pwd_mngt", passphrase = passphrase)
  }
}

#' @importFrom RSQLite SQLite
update_pwd <- function(user, pwd) {
  conn = get_conn()
  on.exit(close_conn(conn))
  passphrase <- .tok$get_passphrase()
  if (!is.null(conn)) {
    res_pwd <- try({
      users <- read_db_decrypt(conn, name = "credentials", passphrase = passphrase)
      ind_user <- users$user %in% user
      if (identical(users$password[ind_user], pwd)) {
        return(list(result = FALSE))
      }
      if(!"character" %in% class(users$password)){
        users$password <- as.character(users$password)
      }
      if(!"is_hashed_password" %in% colnames(users)){
        users$is_hashed_password <- FALSE
      }
      users$password[ind_user] <- pwd
      users$is_hashed_password[ind_user] <- FALSE
      write_db_encrypt(conn, value = users, name = "credentials", passphrase = passphrase)
      force_chg_pwd(user, FALSE)
    }, silent = TRUE)
    return(list(result = !inherits(res_pwd, "try-error")))
  } else {
    return(list(result = FALSE))
  }
}


#' @importFrom RSQLite SQLite
save_logs <- function(token) {
  conn = get_conn()
  on.exit(close_conn(conn))
  passphrase <- .tok$get_passphrase()
  user <- .tok$get_user(token)
  if (!is.null(conn)) {
    res_logs <- try({
      logs <- read_db_decrypt(conn = conn, name = "logs", passphrase = passphrase)
      # patch for old logs database
      if(!"status" %in% colnames(logs)){
        if(nrow(logs) > 0){
          logs$status <- "Success"
        } else {
          logs$status <- character(0)
        }
      }
      
      # check if current admin user
      date_time <- as.character(Sys.time())
      date_day <- substring(date_time, 1, 10)
      logs_day <- substring(logs$server_connected, 1, 10)
      already_user_token <- any(logs$user %in% user & logs_day %in% date_day & logs$token %in% token)
     
      if(!already_user_token){
        logs <- rbind(logs, data.frame(
          user = user,
          server_connected = date_time,
          token = token,
          logout = NA_character_,
          app = get_appname(),
          status = "Success",
          stringsAsFactors = FALSE
        ))
        write_db_encrypt(conn = conn, value = logs, name = "logs", passphrase = passphrase)
      }
    }, silent = TRUE)
    if (inherits(res_logs, "try-error")) {
      warning(paste(
        "shinymanager: unable to save logs | error:", attr(res_logs, "condition")$message
      ), call. = FALSE)
    }
  }
}

save_logs_failed <- function(user, status = "Failed") {
  conn = get_conn()
  on.exit(close_conn(conn))
  passphrase <- .tok$get_passphrase()
  if (!is.null(conn)) {
    res_logs <- try({
      logs <- read_db_decrypt(conn = conn, name = "logs", passphrase = passphrase)
      # patch for old logs database
      if(!"status" %in% colnames(logs)){
        if(nrow(logs) > 0){
          logs$status <- "Success"
        } else {
          logs$status <- character(0)
        }
      }
      logs <- rbind(logs, data.frame(
        user = user,
        server_connected = as.character(Sys.time()),
        token = NA_character_,
        logout = NA_character_,
        app = get_appname(),
        status = status,
        stringsAsFactors = FALSE
      ))
      write_db_encrypt(conn = conn, value = logs, name = "logs", passphrase = passphrase)
    }, silent = TRUE)
    
    if (inherits(res_logs, "try-error")) {
      warning(paste(
        "shinymanager: unable to save logs | error:", attr(res_logs, "condition")$message
      ), call. = FALSE)
    }
  }
}

#' @importFrom RSQLite SQLite
logout_logs <- function(token) {
  conn = get_conn()
  on.exit(close_conn(conn))
  passphrase <- .tok$get_passphrase()
  if (!is.null(conn)) {
    res_logs <- try({
      logs <- read_db_decrypt(conn = conn, name = "logs", passphrase = passphrase)
      logs$logout[logs$token  %in% token] <- as.character(Sys.time())
      write_db_encrypt(conn = conn, value = logs, name = "logs", passphrase = passphrase)
    }, silent = TRUE)
    if (inherits(res_logs, "try-error")) {
      warning(paste(
        "shinymanager: unable to save logs | error:", attr(res_logs, "condition")$message
      ), call. = FALSE)
    }
  }
}


#' Simple password generation
#'
#' @param n Number of password(s)
#'
#' @return a \code{character}
#' @export
#'
#' @importFrom openssl base64_encode rand_bytes
#'
#' @examples
#' generate_pwd()
#'
#' generate_pwd(3)
generate_pwd <- function(n = 1) {
  replicate(n = n, base64_encode(rand_bytes(6)))
}


validate_pwd <- function(pwd) {
  all(vapply(
    X = c("[0-9]+", "[a-z]+", "[A-Z]+", ".{6,}"),
    FUN = grepl, x = pwd, FUN.VALUE = logical(1)
  ))
}




