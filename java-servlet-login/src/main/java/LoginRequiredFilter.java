import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;

@WebFilter(urlPatterns = "*.do")
public class LoginRequiredFilter implements Filter {

    public void destroy() {
    	LoginDao.closeConnection();
    }

    public void doFilter(ServletRequest servletRequest,
            ServletResponse servletResponse, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;

        if (request.getSession().getAttribute("name") != null) {
            chain.doFilter(servletRequest, servletResponse);
        } else {
            request.getRequestDispatcher("/login.do").forward(servletRequest,servletResponse);
        }
    }

    public void init(FilterConfig arg0) throws ServletException {
    }

}