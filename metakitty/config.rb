activate :bh
set :css_dir, 'stylesheets'
set :js_dir, 'javascripts'
set :images_dir, 'images'

# Since this is a project page, all links should be relative.
set :relative_links, true

activate :deploy do |deploy|
  deploy.method = :git
  deploy.remote = 'upstream'
end

configure :build do
  activate :relative_assets
end
